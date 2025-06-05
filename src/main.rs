
use windows::{
    Win32::{
        Foundation::CloseHandle,
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next,
                TH32CS_SNAPPROCESS,
            },
            Memory::{GetProcessHeap, HEAP_NO_SERIALIZE, HeapCompact, SetProcessWorkingSetSizeEx},
            Threading::{
                GetCurrentProcess, OpenProcess, PROCESS_QUERY_INFORMATION,
                 PROCESS_TERMINATE, TerminateProcess,
            },
        },
    },
    core::Result,
}; // 添加sysinfo用于CPU监控


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
    "Code.exe",      // VS Code主进程[12,13]
    "devenv.exe",    // Visual Studio
    "pycharm64.exe", // PyCharm
    "Steam++.exe",
    // 浏览器
    "chrome.exe",  // Chrome浏览器主进程[9,11]
    "msedge.exe",  // Edge浏览器
    "firefox.exe", // Firefox
    // 通讯软件
    "WeChat.exe",    // 微信主进程
    "WeChatWeb.exe", // 微信Web进程
    "QQ.exe",        // QQ
    "DingTalk.exe",  // 钉钉
    // 多媒体工具
];

fn main() -> Result<()> {

    // 1. 结束非关键进程
    terminate_non_critical_processes()?;

    // // 2. 清理系统工作集内存
    compact_system_memory()?;

    println!("内存清理完成");
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


