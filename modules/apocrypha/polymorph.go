package apocrypha

import (
	"fmt"
	"os/exec"
)

func PolymorphPIC(PIC_files []string) {
	fmt.Println("Compiling modules to ASM...")
	var asm_to_poly string
	for i := 0; i < len(PIC_files); i++ {
		//x86_64-w64-mingw32-gcc -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -S -masm=intel custom.pic
		asm_to_poly += "./output/" + PIC_files[i] + ".s "
		gcc_args := []string{"x86_64-w64-mingw32-gcc", "./output/" + PIC_files[i] + ".c", "-Wall", "-m64", "-ffunction-sections", "-fno-asynchronous-unwind-tables", "-nostdlib", "-fno-ident", "-O2", "-S", "-o", "./output/" + PIC_files[i] + ".s", "-masm=intel"}
		gcc_cmd := exec.Command(gcc_args[0], gcc_args[1:]...)
		gcc_err := gcc_cmd.Run()
		if gcc_err != nil {
			panic(gcc_err)
		}
	}
	for i := 0; i < len(PIC_files); i++ {
		//./_lib/SpiderPIC/spiderpic -asm custom.s -o custom.c -pf 5
		fmt.Println("Polymorphing "+PIC_files[i]+"...")
		poly_args := []string{"./_lib/SpiderPIC/spiderpic", "-asm", "./output/" + PIC_files[i] + ".s", "-o", "./output/" + PIC_files[i] + ".s","-pf","5" }
		poly_cmd := exec.Command(poly_args[0], poly_args[1:]...)
		poly_err := poly_cmd.Run()
		if poly_err != nil {
			panic(poly_err)
		}
	}
}