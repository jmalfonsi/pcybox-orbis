use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    thread,
    time::Duration,
};

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Resolution {
    pub direction: &'static str,
    pub process: Option<ProcInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpFlow {
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct LocalEndpoint {
    ip: Ipv4Addr,
    port: u16,
}

#[derive(Default)]
pub struct ProcessSnapshot {
    tcp: HashMap<TcpFlow, ProcInfo>,
    tcp_local: HashMap<LocalEndpoint, ProcInfo>,
    udp_local: HashMap<LocalEndpoint, ProcInfo>,
    local_ips: HashSet<Ipv4Addr>,
    pub table_entries: usize,
}

pub type SharedSnapshot = Arc<RwLock<ProcessSnapshot>>;

pub fn new_shared_snapshot() -> SharedSnapshot {
    Arc::new(RwLock::new(ProcessSnapshot::default()))
}

pub fn spawn_refresh(snapshot: SharedSnapshot, refreshes: Arc<AtomicU64>) {
    thread::Builder::new()
        .name("orbis-process-table".into())
        .spawn(move || loop {
            match read_process_snapshot() {
                Ok(next) => {
                    if let Ok(mut guard) = snapshot.write() {
                        *guard = next;
                    }
                    refreshes.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => eprintln!("[process] refresh failed: {e}"),
            }
            thread::sleep(Duration::from_millis(500));
        })
        .expect("failed to spawn process table thread");
}

pub fn refresh_now(snapshot: &SharedSnapshot) -> Result<(), String> {
    let next = read_process_snapshot()?;
    *snapshot
        .write()
        .map_err(|_| "process snapshot lock poisoned".to_string())? = next;
    Ok(())
}

pub fn resolve(
    snapshot: &SharedSnapshot,
    protocol: &str,
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> Option<Resolution> {
    let guard = snapshot.read().ok()?;

    if protocol == "TCP" {
        let outbound = TcpFlow {
            local_ip: src_ip,
            local_port: src_port,
            remote_ip: dst_ip,
            remote_port: dst_port,
        };
        if let Some(p) = guard.tcp.get(&outbound) {
            return Some(Resolution {
                direction: "out",
                process: Some(p.clone()),
            });
        }

        let inbound = TcpFlow {
            local_ip: dst_ip,
            local_port: dst_port,
            remote_ip: src_ip,
            remote_port: src_port,
        };
        if let Some(p) = guard.tcp.get(&inbound) {
            return Some(Resolution {
                direction: "in",
                process: Some(p.clone()),
            });
        }

        if let Some(p) = lookup_endpoint(&guard.tcp_local, src_ip, src_port) {
            return Some(Resolution {
                direction: "out",
                process: Some(p.clone()),
            });
        }
        if let Some(p) = lookup_endpoint(&guard.tcp_local, dst_ip, dst_port) {
            return Some(Resolution {
                direction: "in",
                process: Some(p.clone()),
            });
        }
    } else if protocol == "UDP" {
        if let Some(p) = lookup_endpoint(&guard.udp_local, src_ip, src_port) {
            return Some(Resolution {
                direction: "out",
                process: Some(p.clone()),
            });
        }
        if let Some(p) = lookup_endpoint(&guard.udp_local, dst_ip, dst_port) {
            return Some(Resolution {
                direction: "in",
                process: Some(p.clone()),
            });
        }
    }

    if guard.local_ips.contains(&src_ip) {
        return Some(Resolution {
            direction: "out",
            process: None,
        });
    }
    if guard.local_ips.contains(&dst_ip) {
        return Some(Resolution {
            direction: "in",
            process: None,
        });
    }

    None
}

pub fn table_entries(snapshot: &SharedSnapshot) -> usize {
    snapshot.read().map(|g| g.table_entries).unwrap_or(0)
}

fn lookup_endpoint<'a>(
    table: &'a HashMap<LocalEndpoint, ProcInfo>,
    ip: Ipv4Addr,
    port: u16,
) -> Option<&'a ProcInfo> {
    table
        .get(&LocalEndpoint { ip, port })
        .or_else(|| table.get(&LocalEndpoint {
            ip: Ipv4Addr::UNSPECIFIED,
            port,
        }))
}

#[cfg(windows)]
fn read_process_snapshot() -> Result<ProcessSnapshot, String> {
    use std::{ffi::c_void, mem::size_of, ptr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER},
        NetworkManagement::IpHelper::{
            GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID,
            MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
        },
        System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    };

    const AF_INET: u32 = 2;

    fn port(v: u32) -> u16 {
        u16::from_be(v as u16)
    }

    fn ip(v: u32) -> Ipv4Addr {
        Ipv4Addr::from(v.to_be())
    }

    unsafe fn query_table<F>(mut call: F) -> Result<Vec<u8>, String>
    where
        F: FnMut(*mut c_void, *mut u32) -> u32,
    {
        let mut size = 0u32;
        let first = call(ptr::null_mut(), &mut size);
        if first != ERROR_INSUFFICIENT_BUFFER && first != 0 {
            return Err(format!("IP Helper sizing call failed with code {first}"));
        }
        if size < 4 {
            return Ok(vec![0; 4]);
        }
        let mut buffer = vec![0u8; size as usize];
        let status = call(buffer.as_mut_ptr().cast(), &mut size);
        if status != 0 {
            return Err(format!("IP Helper table call failed with code {status}"));
        }
        buffer.truncate(size as usize);
        Ok(buffer)
    }

    fn process_name(pid: u32, cache: &mut HashMap<u32, Option<String>>) -> Option<String> {
        if let Some(v) = cache.get(&pid) {
            return v.clone();
        }

        let value = unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                None
            } else {
                let mut buf = vec![0u16; 32_768];
                let mut len = buf.len() as u32;
                let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len);
                CloseHandle(handle);
                if ok == 0 || len == 0 {
                    None
                } else {
                    let full = String::from_utf16_lossy(&buf[..len as usize]);
                    Path::new(&full)
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .or(Some(full))
                }
            }
        };

        cache.insert(pid, value.clone());
        value
    }

    let tcp_buf = unsafe {
        query_table(|table, size| {
            GetExtendedTcpTable(table, size, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
        })?
    };
    let udp_buf = unsafe {
        query_table(|table, size| {
            GetExtendedUdpTable(table, size, 0, AF_INET, UDP_TABLE_OWNER_PID, 0)
        })?
    };

    let mut out = ProcessSnapshot::default();
    let mut names: HashMap<u32, Option<String>> = HashMap::new();

    if tcp_buf.len() >= 4 {
        let count = u32::from_ne_bytes(tcp_buf[0..4].try_into().unwrap()) as usize;
        let row_size = size_of::<MIB_TCPROW_OWNER_PID>();
        for idx in 0..count {
            let off = 4 + idx * row_size;
            if off + row_size > tcp_buf.len() {
                break;
            }
            let row = unsafe {
                ptr::read_unaligned(tcp_buf.as_ptr().add(off).cast::<MIB_TCPROW_OWNER_PID>())
            };
            let local_ip = ip(row.dwLocalAddr);
            let remote_ip = ip(row.dwRemoteAddr);
            let local_port = port(row.dwLocalPort);
            let remote_port = port(row.dwRemotePort);
            let proc = ProcInfo {
                pid: row.dwOwningPid,
                name: process_name(row.dwOwningPid, &mut names),
            };

            if !local_ip.is_unspecified() {
                out.local_ips.insert(local_ip);
            }
            out.tcp_local.insert(
                LocalEndpoint {
                    ip: local_ip,
                    port: local_port,
                },
                proc.clone(),
            );
            if remote_port != 0 {
                out.tcp.insert(
                    TcpFlow {
                        local_ip,
                        local_port,
                        remote_ip,
                        remote_port,
                    },
                    proc,
                );
            }
            out.table_entries += 1;
        }
    }

    if udp_buf.len() >= 4 {
        let count = u32::from_ne_bytes(udp_buf[0..4].try_into().unwrap()) as usize;
        let row_size = size_of::<MIB_UDPROW_OWNER_PID>();
        for idx in 0..count {
            let off = 4 + idx * row_size;
            if off + row_size > udp_buf.len() {
                break;
            }
            let row = unsafe {
                ptr::read_unaligned(udp_buf.as_ptr().add(off).cast::<MIB_UDPROW_OWNER_PID>())
            };
            let local_ip = ip(row.dwLocalAddr);
            let local_port = port(row.dwLocalPort);
            let proc = ProcInfo {
                pid: row.dwOwningPid,
                name: process_name(row.dwOwningPid, &mut names),
            };
            if !local_ip.is_unspecified() {
                out.local_ips.insert(local_ip);
            }
            out.udp_local.insert(
                LocalEndpoint {
                    ip: local_ip,
                    port: local_port,
                },
                proc,
            );
            out.table_entries += 1;
        }
    }

    out.local_ips.insert(Ipv4Addr::LOCALHOST);
    Ok(out)
}

#[cfg(not(windows))]
fn read_process_snapshot() -> Result<ProcessSnapshot, String> {
    Err("process attribution is currently Windows-only".into())
}
