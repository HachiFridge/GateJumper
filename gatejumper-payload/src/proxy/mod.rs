/// Generates a naked global_asm proxy trampoline to jump to the real function.
macro_rules! proxy_proc {
    ($name:ident, $orig_var_name:ident) => {
        static mut $orig_var_name: usize = 0;
        std::arch::global_asm!(
            concat!(".globl ", stringify!($name)),
            concat!(stringify!($name), ":"),
            "    jmp qword ptr [rip + {}]",
            sym $orig_var_name
        );
    }
}

pub mod version;
