ENTRY(_start)
MEMORY {
  TEXT (rx) : ORIGIN = 0x10000000, LENGTH = 256M
  ADVICE (rw) : ORIGIN = 0x20000000, LENGTH = 64K
  RAM (rw) : ORIGIN = 0x40000000, LENGTH = 4M
}
SECTIONS {
  .text : { KEEP(*(.text._start)) *(.text .text.*) } > TEXT
  .input (NOLOAD) : { __input = .; . += 32; } > RAM
  .data : {
    *(.rodata .rodata.* .srodata .srodata.*)
    *(.data .data.* .sdata .sdata.*)
    *(.got .got.*)
  } > RAM
  .bss (NOLOAD) : { *(.bss .bss.* .sbss .sbss.*) } > RAM
  __heap_start = ALIGN(16);
  __heap_end = ORIGIN(RAM) + LENGTH(RAM) - 256K;
  __stack_top = ORIGIN(RAM) + LENGTH(RAM);
  __advice = ORIGIN(ADVICE);
  __advice_top = ORIGIN(ADVICE) + LENGTH(ADVICE);
  ASSERT(__heap_start < __heap_end, "guest image leaves no heap")
  /DISCARD/ : { *(.eh_frame .eh_frame_hdr .comment .riscv.attributes) }
}
