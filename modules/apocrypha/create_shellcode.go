package apocrypha
import (
	"fmt"
	"os"
	"os/exec"
	"bytes"
	"text/template"
)

type AdjustStackTemplate struct {
	TemplateHelperModules []string
	TemplateCallModules []string
}

func CreateEntryPatch(adjust_stack_template AdjustStackTemplate) {
	fmt.Println("Creating adjuststack.asm...")
	t, err := template.ParseFiles("utility_templates/adjuststack.asm.template")
	if err != nil {
		panic(err)
	}
	f, err := os.Create("output/adjuststack.asm")
	if err != nil {
	  panic(err)
	}
	err = t.Execute(f, adjust_stack_template)
	if err != nil {
		panic(err)
	}
	f.Close()
  
	fmt.Println("Creating linker.ld...")
	t, err = template.ParseFiles("utility_templates/linker.ld.template")
	if err != nil {
		panic(err)
	}
	f, err = os.Create("output/linker.ld")
	if err != nil {
	  panic(err)
	}
	err = t.Execute(f, adjust_stack_template)
	if err != nil {
		panic(err)
	}
	f.Close()  
}	

func CreateShellcode(config YamlConfig) {
	AntiCommandInject([]string{config.InFile, config.OutFilename})
	var errb bytes.Buffer
	// Create entry patch
	adjust_stack_template := AdjustStackTemplate{ []string{}, []string{} }

	// Antianalysis
	if config.ShellcodeOpts.Antianalysis {
		adjust_stack_template.TemplateCallModules = append(adjust_stack_template.TemplateCallModules, "antianalysis")
		fmt.Println("Copying antianalysis code...")
		FileCopy("./templates/antianalysis.cpp.template", "./output/antianalysis.cpp")
	}
	// EDR hooks
	switch config.ShellcodeOpts.EdrHooks {
		case "":
			fmt.Println("No EDR Hook evasion selected")
		default:
			fmt.Println("[+] Selected EDR Hook evasion: "+config.ShellcodeOpts.EdrHooks)
			syscall_structs := ExtractSyscallIds(config.ShellcodeOpts.EdrTool, "_lib/ntdll.dll")
			TemplateEdrHooks(config, syscall_structs)
			adjust_stack_template.TemplateCallModules = append(adjust_stack_template.TemplateCallModules, config.ShellcodeOpts.EdrHooks)
	}
	// Hide callstack - WIP
	if config.ShellcodeOpts.HideCallStack {
		fmt.Println("[+] Selected Hide Call Stack evasion")
		FileCopy("utility_templates/hidecallstack.asm.template", "./output/hidecallstack.asm")
		FileCopy("./_lib/callstack_evade.h", "./output/callstack_evade.h")
		fmt.Println("Compiling hidecallstack.asm...")
		hidecallstack_args := []string{"nasm", "-f", "win64", "./output/hidecallstack.asm", "-o", "./output/hidecallstack.o"}
		nasm_cmd := exec.Command(hidecallstack_args[0], hidecallstack_args[1:]...)
		nasm_cmd.Stderr = &errb
		nasm_err := nasm_cmd.Run()
		if nasm_err != nil {
			panic(errb.String())
		}
		adjust_stack_template.TemplateHelperModules = append(adjust_stack_template.TemplateHelperModules, "hidecallstack")
	}

	adjust_stack_template.TemplateCallModules = append(adjust_stack_template.TemplateCallModules, "custom")
	fmt.Println("Copying input code file...")
	FileCopy(config.InFile, "./output/custom.cpp")

	// Template out adjuststack.asm
	CreateEntryPatch(adjust_stack_template)

	//Compile adjuststack.asm
	fmt.Println("Compiling adjuststack.asm...")
	adjstack_args := []string{"nasm", "-f", "win64", "./output/adjuststack.asm", "-o", "./output/adjuststack.o"}
	nasm_cmd := exec.Command(adjstack_args[0], adjstack_args[1:]...)
	nasm_cmd.Stderr = &errb
	nasm_err := nasm_cmd.Run()
	if nasm_err != nil {
		panic(errb.String())
	}

	//copy headers to output
	FileCopy("./_lib/APIresolve.h", "./output/APIresolve.h")
	FileCopy("./_lib/ntdll.h", "./output/ntdll.h")
	pic_format := ".cpp"

	//if polymorph is set then compile PIC c files as ASM, run through spiderPIC, and recompile to object file
	if config.ShellcodeOpts.Polymorph {
		pic_format = ".s"
		PolymorphPIC(adjust_stack_template.TemplateCallModules)
	}

	//Compiling modules (underscore ignores the dir otherwise the C files get pulled in during Go Build)
	fmt.Println("Compiling modules...")
	//populate objects_to_link
	objects_to_link := []string{"./output/adjuststack.o"}
	for i := 0; i < len(adjust_stack_template.TemplateCallModules); i++ {
		objects_to_link = append(objects_to_link, "./output/" + adjust_stack_template.TemplateCallModules[i] + ".o")
	}
	for i := 0; i < len(adjust_stack_template.TemplateHelperModules); i++ {
		objects_to_link = append(objects_to_link, "./output/" + adjust_stack_template.TemplateHelperModules[i] + ".o")
	}

	for i := 0; i < len(adjust_stack_template.TemplateCallModules); i++ {
		gcc_args := []string{"x86_64-w64-mingw32-g++", "./output/" + adjust_stack_template.TemplateCallModules[i] + pic_format, "-Wall", "-m64", "-ffunction-sections", "-fno-asynchronous-unwind-tables", "-nostdlib", "-fno-ident", "-O2", "-c", "-o", "./output/" + adjust_stack_template.TemplateCallModules[i] + ".o", "-Wl,-T./output/linker.ld,--no-seh"}
		if pic_format == ".s" {
			gcc_args = append(gcc_args, "-masm=intel")
		}
		gcc_cmd := exec.Command(gcc_args[0], gcc_args[1:]...)
		gcc_cmd.Stderr = &errb
		gcc_err := gcc_cmd.Run()
		if gcc_err != nil {
			fmt.Println(gcc_args)
			panic(errb.String())
		}
		fmt.Println("Done compiling: "+adjust_stack_template.TemplateCallModules[i] + pic_format)
	}

	//now link all the object files together
	fmt.Println("Linking modules...")
	ld_args := []string{"x86_64-w64-mingw32-ld", "-s"}
	ld_args = append(ld_args, objects_to_link...)
	ld_args = append(ld_args, []string{"-o", "./output/PIC.exe"}...)

	ld_cmd := exec.Command(ld_args[0], ld_args[1:]...)
	ld_cmd.Stderr = &errb
	ld_err := ld_cmd.Run()
	if ld_err != nil {
		panic(errb.String())
	}

	//Dump .text section to get shellcode
	objcpy_args := []string{"objcopy", "-j", ".text", "-O", "binary", "./output/PIC.exe", "./output/" + config.OutFilename + ".bin"}
	objcpy_cmd := exec.Command(objcpy_args[0], objcpy_args[1:]...)
	objcpy_cmd.Stderr = &errb
	objcpy_err := objcpy_cmd.Run()
	if objcpy_err != nil {
		panic(errb.String())
	}
}