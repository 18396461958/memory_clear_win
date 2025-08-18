
use std::path::Path;

use windows::{
    Win32::{
        Foundation::CloseHandle,
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next,
                TH32CS_SNAPPROCESS,
            },
            Memory::{
                GetProcessHeap, HEAP_NO_SERIALIZE, 
                HeapCompact, SetProcessWorkingSetSizeEx
            },
            Threading::{
                GetCurrentProcess, OpenProcess, PROCESS_QUERY_INFORMATION,
                PROCESS_VM_OPERATION, PROCESS_TERMINATE, TerminateProcess,
            },
        },
    },
    core::Result,
};



// 系统关键进程白名单（防止误杀导致系统崩溃）
const PROTECTED_PROCESSES: &[&str] = &[
    // 系统核心进程
    "System",
    "svchost.exe",
    "wininit.exe",
    "csrss.exe",
    "lsass.exe",
    "winlogon.exe",
    // 开发工具
    // 浏览器
    "chrome.exe",  // Chrome浏览器主进程
    "msedge.exe",  // Edge浏览器
    "firefox.exe", // Firefox
    // 通讯软件
    "WeChat.exe",    // 微信主进程
    "WeChatWeb.exe", // 微信Web进程
    "QQ.exe",        // QQ
    "DingTalk.exe",  // 钉钉
    "Steam++.exe",
    "Steam++.Accelerator.exe",
    "conhost.exe",
    "cmd.exe",
    "powershell.exe",
    "rust-analyzer.exe",
    "rust-analyzer-proc-macro-srv.exe"


    // 多媒体工具
];

fn main() -> Result<()> {

    // 1. 结束非关键进程
    terminate_non_critical_processes()?;

    // // 2. 清理系统工作集内存
    compact_system_memory()?;

    clear_virtual_memory()?;
    clean_system_caches();
    dynamic_clock_boost(true);

    println!("内存清理完成");
    Ok(())
}




/// 动态调整CPU时钟速度
fn dynamic_clock_boost(enable: bool) {
    unsafe {
        use windows::Win32::{
            Foundation::GetLastError,
            System::Threading::{
                GetCurrentProcess, SetProcessInformation, 
                PROCESS_INFORMATION_CLASS,
                PROCESS_POWER_THROTTLING_STATE,
                PROCESS_POWER_THROTTLING_EXECUTION_SPEED, 
                PROCESS_POWER_THROTTLING_CURRENT_VERSION
            }
        };

        // 使用Windows API定义的枚举值
        const PROCESS_POWER_THROTTLING: PROCESS_INFORMATION_CLASS = 
            PROCESS_INFORMATION_CLASS(0x12); // 0x12是ProcessPowerThrottling的实际值[9,10](@ref)

        let mut throttling_state = PROCESS_POWER_THROTTLING_STATE {
            Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
            ControlMask: if enable { PROCESS_POWER_THROTTLING_EXECUTION_SPEED } else { 0 },
            StateMask: if enable { PROCESS_POWER_THROTTLING_EXECUTION_SPEED } else { 0 },
        };
        
        SetProcessInformation(
            GetCurrentProcess(),
            PROCESS_POWER_THROTTLING, // 使用定义的常量
            &mut throttling_state as *mut _ as _,
            std::mem::size_of::<PROCESS_POWER_THROTTLING_STATE>() as _,
        ).map_err(|_e| {
            eprintln!("SetProcessInformation failed: {:?}", GetLastError());
        }).ok();
    }
}


fn clean_system_caches() {
    // 缩略图缓存
    let thumbnail_cache = Path::new("C:\\Users\\User\\AppData\\Local\\Microsoft\\Windows\\Explorer")
        .join("thumbcache*.db");
    clean_files(thumbnail_cache);

    // DNS 缓存（已移除 unsafe）
    std::process::Command::new("cmd")
        .args(&["/C", "ipconfig", "/flushdns"])
        .spawn()
        .expect("无法刷新DNS缓存");

    // 预取文件
    let prefetch_files = Path::new("C:\\Windows\\Prefetch").join("*.pf");
    clean_files(prefetch_files);
}

/// 清理指定模式的文件
fn clean_files(path_pattern: std::path::PathBuf) {
    if let Some(parent) = path_pattern.parent() {
        if let Some(file_name) = path_pattern.file_name() {
            if let Some(file_name_str) = file_name.to_str() {
                if let Ok(entries) = std::fs::read_dir(parent) {
                    // 使用闭包处理 Result
                    for entry in entries.filter_map(|res| res.ok()) {
                        if let Some(name) = entry.file_name().to_str() {
                            if name.contains(file_name_str.trim_matches('*')) {
                                let _ = std::fs::remove_file(entry.path());
                            }
                        }
                    }
                }
            }
        }
    }
}
/// 新增：清理虚拟内存功能
fn clear_virtual_memory() -> Result<()> {
    // 方法1：清空工作集（将不常用内存移入虚拟内存）
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        let mut entry: PROCESSENTRY32 = PROCESSENTRY32::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                let process_name = decode_process_name(&entry);
                
                // 只清理非保护进程
                if !is_protected(&process_name) {
                    let handle = OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION,
                        false,
                        entry.th32ProcessID,
                    );
                    
                    if let Ok(handle) = handle {
                        // 清空工作集（将物理内存移入虚拟内存）
                        CloseHandle(handle)?;
                    }
                }

                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        CloseHandle(snapshot)?;
    }

    // 方法2：重置进程工作集（强制释放未使用内存）
    unsafe {
        let current_process = GetCurrentProcess();

        // 设置为最小值（!0表示使用物理内存的最小值）
        SetProcessWorkingSetSizeEx(
            current_process,
            !0,
            !0,
            windows::Win32::System::Memory::SETPROCESSWORKINGSETSIZEEX_FLAGS(0),
        )?;
    }

    Ok(())
}

/// 结束非关键进程
fn terminate_non_critical_processes() -> Result<()> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };
    let mut entry: PROCESSENTRY32 = PROCESSENTRY32::default();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    unsafe {
        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                let process_name = decode_process_name(&entry);
                if !is_protected(&process_name) {
                terminate_process(entry.th32ProcessID);
                }

                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    Ok(())
}

/// 终止单个进程
fn terminate_process(pid: u32) {
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, false, pid);
        if let Ok(handle) = handle {
            let _ = TerminateProcess(handle, 1);
            let _ = CloseHandle(handle);
        }
    }
}

/// 清理系统内存缓存
fn compact_system_memory() -> Result<()> {
    unsafe {
        let heap = GetProcessHeap()?; // 使用?处理Result
        HeapCompact(heap, HEAP_NO_SERIALIZE);

        // 使用SetProcessWorkingSetSizeEx替代SetProcessWorkingSetSize
        let current_process = GetCurrentProcess();
        SetProcessWorkingSetSizeEx(
            current_process,
            !0,
            !0,
            windows::Win32::System::Memory::SETPROCESSWORKINGSETSIZEEX_FLAGS(0),
        )?;
    }
    Ok(())
}

/// 解码进程名称
fn decode_process_name(entry: &PROCESSENTRY32) -> String {
    entry.szExeFile
        .iter()
        .take_while(|&&c| c != 0) // 遇到空字符停止
        .map(|&c| c as u8 as char)
        .collect::<String>()
}
fn is_protected(process_name: &str) -> bool {
    PROTECTED_PROCESSES.iter().any(|&name| {
        // 精确匹配主进程名（忽略大小写）
        process_name.eq_ignore_ascii_case(name) 
        // 额外匹配浏览器子进程（如 chrome.exe:1234）
        || (name == "chrome.exe" && process_name.starts_with("chrome.exe"))
    })
}


