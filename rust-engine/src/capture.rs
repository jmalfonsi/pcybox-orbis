use libloading::Library;
use std::{
    ffi::{c_char, c_int, c_uchar, c_void, CStr, CString},
    net::Ipv4Addr,
    ptr,
    slice,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread,
};
use tokio::sync::mpsc;

const PCAP_ERRBUF_SIZE: usize = 256;
const PCAP_IF_LOOPBACK: u32 = 0x0000_0001;
const DLT_EN10MB: c_int = 1;

#[derive(Debug, Clone)]
pub struct RawPacket {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: &'static str,
    pub size: u32,
}

#[derive(Default)]
pub struct CaptureMetrics {
    pub packets_seen: AtomicU64,
    pub packets_parsed: AtomicU64,
    pub channel_drops: AtomicU64,
}

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut c_void,
    flags: u32,
}

#[repr(C)]
struct PcapTimeval {
    tv_sec: i32,
    tv_usec: i32,
}

#[repr(C)]
struct PcapPkthdr {
    ts: PcapTimeval,
    caplen: u32,
    len: u32,
}

#[repr(C)]
struct Pcap {
    _private: [u8; 0],
}

type PcapFindAllDevs =
    unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int;
type PcapFreeAllDevs = unsafe extern "C" fn(*mut PcapIf);
type PcapOpenLive =
    unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut Pcap;
type PcapNextEx =
    unsafe extern "C" fn(*mut Pcap, *mut *mut PcapPkthdr, *mut *const c_uchar) -> c_int;
type PcapClose = unsafe extern "C" fn(*mut Pcap);
type PcapDatalink = unsafe extern "C" fn(*mut Pcap) -> c_int;

#[cfg(windows)]
unsafe fn load_wpcap() -> Result<Library, String> {
    use std::{os::windows::ffi::OsStrExt, path::PathBuf};
    use windows_sys::Win32::System::LibraryLoader::SetDllDirectoryW;

    // Npcap installs outside the ordinary System32 DLL search directory by
    // default. Put its directory first so wpcap.dll and its Packet.dll
    // dependency resolve to Npcap rather than an old WinPcap installation.
    let windows_dir = std::env::var_os("WINDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let npcap_dir = windows_dir.join("System32").join("Npcap");
    let wide: Vec<u16> = npcap_dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    if SetDllDirectoryW(wide.as_ptr()) != 0 {
        let explicit = npcap_dir.join("wpcap.dll");
        if explicit.exists() {
            if let Ok(lib) = Library::new(&explicit) {
                return Ok(lib);
            }
        }
    }

    // Fallback supports WinPcap-compatible Npcap installs and development
    // environments that already configured PATH/DLL search directories.
    Library::new("wpcap.dll").map_err(|e| {
        format!(
            "cannot load Npcap wpcap.dll (expected under {}): {e}",
            npcap_dir.display()
        )
    })
}

#[cfg(not(windows))]
unsafe fn load_wpcap() -> Result<Library, String> {
    Err("orbis-engine capture is currently Windows-only".into())
}

pub fn start_capture(
    tx: mpsc::Sender<RawPacket>,
    capture_enabled: Arc<AtomicBool>,
    metrics: Arc<CaptureMetrics>,
) -> Result<Vec<String>, String> {
    let adapters = enumerate_adapters()?;
    if adapters.is_empty() {
        return Err("Npcap reported no non-loopback capture adapter".into());
    }

    for adapter in adapters.iter().cloned() {
        let tx = tx.clone();
        let capture_enabled = capture_enabled.clone();
        let metrics = metrics.clone();
        thread::Builder::new()
            .name(format!("orbis-pcap-{}", sanitize_thread_name(&adapter)))
            .spawn(move || {
                if let Err(e) = capture_adapter(&adapter, tx, capture_enabled, metrics) {
                    eprintln!("[capture] {adapter}: {e}");
                }
            })
            .map_err(|e| format!("failed to spawn capture thread: {e}"))?;
    }

    Ok(adapters)
}

fn sanitize_thread_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(20)
        .collect()
}

fn enumerate_adapters() -> Result<Vec<String>, String> {
    unsafe {
        let lib = load_wpcap()?;
        let find_all: PcapFindAllDevs = *lib
            .get(b"pcap_findalldevs\0")
            .map_err(|e| format!("pcap_findalldevs missing: {e}"))?;
        let free_all: PcapFreeAllDevs = *lib
            .get(b"pcap_freealldevs\0")
            .map_err(|e| format!("pcap_freealldevs missing: {e}"))?;

        let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];
        let mut all: *mut PcapIf = ptr::null_mut();
        if find_all(&mut all, errbuf.as_mut_ptr()) != 0 {
            return Err(pcap_error(&errbuf));
        }

        let mut result = Vec::new();
        let mut current = all;
        while !current.is_null() {
            let item = &*current;
            if item.flags & PCAP_IF_LOOPBACK == 0 && !item.name.is_null() {
                if let Ok(name) = CStr::from_ptr(item.name).to_str() {
                    result.push(name.to_owned());
                }
            }
            current = item.next;
        }
        free_all(all);

        result.sort();
        result.dedup();
        Ok(result)
    }
}

fn capture_adapter(
    adapter: &str,
    tx: mpsc::Sender<RawPacket>,
    capture_enabled: Arc<AtomicBool>,
    metrics: Arc<CaptureMetrics>,
) -> Result<(), String> {
    unsafe {
        let lib = load_wpcap()?;
        let open_live: PcapOpenLive = *lib
            .get(b"pcap_open_live\0")
            .map_err(|e| format!("pcap_open_live missing: {e}"))?;
        let next_ex: PcapNextEx = *lib
            .get(b"pcap_next_ex\0")
            .map_err(|e| format!("pcap_next_ex missing: {e}"))?;
        let close: PcapClose = *lib
            .get(b"pcap_close\0")
            .map_err(|e| format!("pcap_close missing: {e}"))?;
        let datalink: PcapDatalink = *lib
            .get(b"pcap_datalink\0")
            .map_err(|e| format!("pcap_datalink missing: {e}"))?;

        let name = CString::new(adapter).map_err(|_| "adapter name contains NUL".to_string())?;
        let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];

        // 262144 avoids truncating normal packets. A short read timeout keeps
        // the thread responsive without busy-polling.
        let handle = open_live(name.as_ptr(), 262_144, 0, 100, errbuf.as_mut_ptr());
        if handle.is_null() {
            return Err(pcap_error(&errbuf));
        }

        let link_type = datalink(handle);
        if link_type != DLT_EN10MB {
            close(handle);
            return Err(format!("unsupported datalink type {link_type}; expected Ethernet"));
        }

        loop {
            let mut header: *mut PcapPkthdr = ptr::null_mut();
            let mut data: *const c_uchar = ptr::null();
            match next_ex(handle, &mut header, &mut data) {
                1 => {
                    if header.is_null() || data.is_null() {
                        continue;
                    }
                    metrics.packets_seen.fetch_add(1, Ordering::Relaxed);
                    if !capture_enabled.load(Ordering::Relaxed) {
                        continue;
                    }

                    let h = &*header;
                    let bytes = slice::from_raw_parts(data, h.caplen as usize);
                    if let Some(mut packet) = parse_ethernet_ipv4(bytes) {
                        packet.size = h.len;
                        metrics.packets_parsed.fetch_add(1, Ordering::Relaxed);
                        if tx.try_send(packet).is_err() {
                            metrics.channel_drops.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                0 => continue,
                -2 => break,
                code => {
                    close(handle);
                    return Err(format!("pcap_next_ex returned {code}"));
                }
            }
        }

        close(handle);
        Ok(())
    }
}

fn pcap_error(buf: &[i8; PCAP_ERRBUF_SIZE]) -> String {
    unsafe {
        CStr::from_ptr(buf.as_ptr())
            .to_string_lossy()
            .trim()
            .to_string()
    }
}

fn parse_ethernet_ipv4(frame: &[u8]) -> Option<RawPacket> {
    if frame.len() < 14 {
        return None;
    }

    let mut ip_offset = 14usize;
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    // Single or stacked 802.1Q / 802.1ad VLAN tags.
    while ethertype == 0x8100 || ethertype == 0x88a8 {
        if frame.len() < ip_offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[ip_offset + 2], frame[ip_offset + 3]]);
        ip_offset += 4;
    }

    if ethertype != 0x0800 || frame.len() < ip_offset + 20 {
        return None;
    }

    let version_ihl = frame[ip_offset];
    if version_ihl >> 4 != 4 {
        return None;
    }
    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < 20 || frame.len() < ip_offset + ihl + 4 {
        return None;
    }

    let fragment = u16::from_be_bytes([frame[ip_offset + 6], frame[ip_offset + 7]]);
    if fragment & 0x1fff != 0 {
        return None;
    }

    let src_ip = Ipv4Addr::new(
        frame[ip_offset + 12],
        frame[ip_offset + 13],
        frame[ip_offset + 14],
        frame[ip_offset + 15],
    );
    let dst_ip = Ipv4Addr::new(
        frame[ip_offset + 16],
        frame[ip_offset + 17],
        frame[ip_offset + 18],
        frame[ip_offset + 19],
    );

    let transport = ip_offset + ihl;
    let src_port = u16::from_be_bytes([frame[transport], frame[transport + 1]]);
    let dst_port = u16::from_be_bytes([frame[transport + 2], frame[transport + 3]]);

    let protocol = match frame[ip_offset + 9] {
        6 => "TCP",
        17 => "UDP",
        _ => return None,
    };

    Some(RawPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        size: frame.len() as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_tcp_ethernet() {
        let mut p = vec![0u8; 14 + 20 + 20];
        p[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        p[14] = 0x45;
        p[23] = 6;
        p[26..30].copy_from_slice(&[192, 168, 1, 10]);
        p[30..34].copy_from_slice(&[1, 1, 1, 1]);
        p[34..36].copy_from_slice(&50_000u16.to_be_bytes());
        p[36..38].copy_from_slice(&443u16.to_be_bytes());

        let parsed = parse_ethernet_ipv4(&p).unwrap();
        assert_eq!(parsed.src_ip, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(parsed.dst_ip, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(parsed.src_port, 50_000);
        assert_eq!(parsed.dst_port, 443);
        assert_eq!(parsed.protocol, "TCP");
    }
}
