package apocrypha
import (
	"fmt"
	"os"
	"os/exec"
	"bytes"
	"text/template"
)

func PrepRustCargo(config YamlConfig, meta_data map[string]interface{}) {
	var errb bytes.Buffer
	if TypeAssertionValidator(meta_data["cargo_file"]) != "string" {
		fmt.Println("cargo_file is not the proper type. It should be a string")
		os.Exit(1)
	}
	if meta_data["cargo_file"].(string) == "" {
		fmt.Println("YAML file has empty strings in required fields. Please fill them in")
		os.Exit(1)
	}
	fmt.Println("Setting up Cargo for new rust project...")
	// Prep template Cargo file
	t, err := template.ParseFiles("./wrappers/"+config.WrapperOpts.Format+"/"+meta_data["cargo_file"].(string))
	if err != nil {
		panic(err)
	}
	//cd into output
	err = os.Chdir("./output")
	if err != nil {
		panic(err)
	}
	// Create new directory
	cargo_args := []string{"cargo", "new", config.OutFilename}
	cargo_cmd := exec.Command(cargo_args[0], cargo_args[1:]...)
	cargo_cmd.Stderr = &errb
	cargo_err := cargo_cmd.Run()
	if cargo_err != nil {
		panic(errb.String())
	}

	// delete old main.rs
	err = os.Remove(config.OutFilename+"/src/main.rs")
    if err != nil {
        panic(err)
    }
	//Copy in new templated source code
	FileCopy(config.OutFilename+".rs", config.OutFilename+"/src/main.rs")
	// delete old Cargo.toml
	err = os.Remove(config.OutFilename+"/Cargo.toml")
    if err != nil {
        panic(err)
    }
	// Template out new Cargo.toml
	cargo_struct := struct {
		Filename string
	}{
		config.OutFilename,
	}
	f, err := os.Create(config.OutFilename+"/Cargo.toml")
	if err != nil {
		panic(err)
	}
	err = t.Execute(f, cargo_struct)
	if err != nil {
		panic(err)
	}
	// cd ..
	err = os.Chdir("../")
	if err != nil {
		panic(err)
	}
}

func CompileXORPrelude(config YamlConfig) {
	var errb bytes.Buffer
	ext_sc_args := []string{"nasm", "-f", "win64", "-o", "./output/xor_prelude.so", "./output/" + config.OutFilename + "-xorprelude.asm"}
	ext_sc_cmd := exec.Command(ext_sc_args[0], ext_sc_args[1:]...)
	ext_sc_cmd.Stderr = &errb
	ext_sc_err := ext_sc_cmd.Run()
	if ext_sc_err != nil {
		fmt.Println(ext_sc_args)
		panic(errb.String())
	}
	fmt.Println("Done compiling: xor_prelude.asm")
	// Link
	ext_sc_args = []string{"x86_64-w64-mingw32-ld", "-s", "-o", "./output/xor_prelude.exe", "./output/xor_prelude.so"}
	ext_sc_cmd = exec.Command(ext_sc_args[0], ext_sc_args[1:]...)
	ext_sc_cmd.Stderr = &errb
	ext_sc_err = ext_sc_cmd.Run()
	if ext_sc_err != nil {
		fmt.Println(ext_sc_args)
		panic(errb.String())
	}
	fmt.Println("Done linking: xor_prelude.so")
	// Dump .text
	ext_sc_args = []string{"x86_64-w64-mingw32-objcopy", "--only-section=.text", "-O", "binary", "./output/xor_prelude.exe", "./output/xor_prelude.bin"}
	ext_sc_cmd = exec.Command(ext_sc_args[0], ext_sc_args[1:]...)
	ext_sc_cmd.Stderr = &errb
	ext_sc_err = ext_sc_cmd.Run()
	if ext_sc_err != nil {
		fmt.Println(ext_sc_args)
		panic(errb.String())
	}
	fmt.Println("Dumped .text from: xor_prelude.exe")
	// NASM is adding extra bad operands at the end idk why but strip em out
	shellcode, err := os.ReadFile("./output/xor_prelude.bin")
	if err != nil {
		panic(err)
	}

	fmt.Println("Prepending xor_prelude to ./output/"+config.OutFilename+".bin...")
	sig := []byte{0x0f, 0x1f, 0x00, 0xff, 0xff}
	offset := bytes.Index(shellcode, sig)
	xor_decryptor := shellcode[0:offset]
	//Rename the old file
	err = os.Rename("./output/"+config.OutFilename+".bin", "./output/prependme.bin")
	if err != nil {
		panic(err)
	}
	PrependToFile(xor_decryptor, "./output/prependme.bin", "./output/"+config.OutFilename+".bin")
}

func WrapperCompiler(config YamlConfig, meta_data map[string]interface{}) {
	var errb bytes.Buffer
	fmt.Println("Compiling "+ config.OutFilename + "." + meta_data["filetype"].(string) + "...")
	switch meta_data["filetype"].(string) {
		case "exe":
			switch meta_data["language"].(string) {
				case "cpp":
					wrapper_args := []string{"x86_64-w64-mingw32-g++", "-Wall", "-O0", "./output/" + config.OutFilename + "." + meta_data["language"].(string), "-o", "./output/" + config.OutFilename + "." + meta_data["filetype"].(string)}
					wrapper_cmd := exec.Command(wrapper_args[0], wrapper_args[1:]...)
					wrapper_cmd.Stderr = &errb
					wrapper_err := wrapper_cmd.Run()
					if wrapper_err != nil {
						panic(errb.String())
					}
				case "go":
					fmt.Println("something")
				case "rs":
					PrepRustCargo(config, meta_data)
					fmt.Println("Building rust exe...")
					// Build
					wrapper_args := []string{"cargo","build", "--target", "x86_64-pc-windows-gnu", "--manifest-path=./output/"+config.OutFilename+"/Cargo.toml"}
					wrapper_cmd := exec.Command(wrapper_args[0], wrapper_args[1:]...)
					wrapper_cmd.Stderr = &errb
					wrapper_err := wrapper_cmd.Run()
					if wrapper_err != nil {
						panic(errb.String())
					}
					// Copy .exe into output directory
					FileCopy("./output/"+config.OutFilename+"/target/x86_64-pc-windows-gnu/debug/"+config.OutFilename+".exe","./output/"+config.OutFilename+".exe")
			}
		case "dll":
			switch meta_data["language"].(string) {
				case "cpp":
					wrapper_args := []string{"x86_64-w64-mingw32-g++", "-Wall", "-O0", "-shared", "./output/" + config.OutFilename + ".cpp", "-o", "./output/" + config.OutFilename + ".dll"}
					wrapper_cmd := exec.Command(wrapper_args[0], wrapper_args[1:]...)
					wrapper_cmd.Stderr = &errb
					wrapper_err := wrapper_cmd.Run()
					if wrapper_err != nil {
						panic(errb.String())
					}
				case "go":
					wrapper_args := []string{"env", "GOPRIVATE=*", "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=1", "CC=x86_64-w64-mingw32-gcc", "CXX=x86_64-w64-mingw32-g++", "go", "build", "-o", "./output/" + config.OutFilename + ".dll", "-buildmode=c-shared", "-ldflags", "-w -s", "./output/" + config.OutFilename + ".go"}
					wrapper_cmd := exec.Command(wrapper_args[0], wrapper_args[1:]...)
					wrapper_cmd.Stderr = &errb
					wrapper_err := wrapper_cmd.Run()
					if wrapper_err != nil {
						panic(errb.String())
					}
			}
	}
}