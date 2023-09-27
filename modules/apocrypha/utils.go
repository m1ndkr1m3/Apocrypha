package apocrypha

import (
  "os"
  "os/exec"
  "io"
  "bufio"
  "bytes"
  "unicode/utf8"
  "encoding/hex"
  "encoding/binary"
  peparser "github.com/saferwall/pe"
  "regexp"
  "fmt"
  "math/rand"
  "time"
)

// Struct for stomping hooked syscalls
type SyscallStruct struct {
	FunctionName string
	Djb2Name []byte		// 4 bytes
	RawOffset uint32
	FunctionBytes []byte	// 8 bytes
	SyscallId []byte
}

// yaml config structure
type YamlConfig struct {
	Mode      string `yaml:"mode"`
	InFile       string `yaml:"in_file"`
	OutFilename  string `yaml:"out_filename"`
	Encrypt      string `yaml:"encrypt"`
	Debug        bool   `yaml:"debug"`
	ShellcodeOpts struct {
		EdrHooks     string `yaml:"edr_hooks"`
		EdrTool      string `yaml:"edr_tool"`
		HideCallStack bool `yaml:"hide_call_stack"`
		Polymorph    bool `yaml:"polymorph"`
		Antianalysis bool `yaml:"antianalysis"`
	} `yaml:"shellcode_opts"`
	WrapperOpts struct {
		Format string `yaml:"format"`
	} `yaml:"wrapper_opts"`
}

func djb2Hash(str string) uint32 {
	hash := uint32(5381)

	for _, char := range str {
		hash = (hash << 5) + hash + uint32(char)
	}

	return hash
}

func StrSliceContains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}


func CleanupOutputDir(config YamlConfig, meta_data map[string]interface{}, deleteAll bool) {
	var errb bytes.Buffer
	allowlist := []string{".gitignore"} 
	if !deleteAll {
		var extension string
		if config.Mode == "shellcode" {
			extension = "bin"
			allowlist = append(allowlist, config.OutFilename+"."+extension)
		} else {
			if TypeAssertionValidator(meta_data["filetype"]) != "string" {
				fmt.Println("filetype is not the proper type. It should be a string")
				os.Exit(1)
			}
			allowlist = append(allowlist, config.OutFilename+"."+meta_data["filetype"].(string))
			switch meta_data["filetype"].(string) {
				case "inject":
					extension = "o"
					allowlist = append(allowlist, config.OutFilename+"."+extension)
					allowlist = append(allowlist, "inject_shellcode.bin")
					allowlist = append(allowlist, config.OutFilename+"_writemem."+ extension) 
					allowlist = append(allowlist, config.OutFilename+"_inject."+ extension)
			}
		}
	}
	f, err := os.Open("./output/")
	if err != nil {
		panic(err)
	}
	files, err := f.Readdir(0)
	if err != nil {
		panic(err)
	}
	for _, v := range files {
		//Don't delete .gitignore or the final file output
		if StrSliceContains(allowlist, v.Name()) == false {
			if v.IsDir() == true {
				// os.RemoveAll isn't working
				rm_args := []string{"rm", "-rf", "./output/"+v.Name()}
				rm_cmd := exec.Command(rm_args[0], rm_args[1:]...)
				rm_cmd.Stderr = &errb
				rm_err := rm_cmd.Run()
				if rm_err != nil {
					panic(errb.String())
				}
			} else {
				os.Remove("./output/" + v.Name())
			}
		}
	}
}

func FileCopy(fromfile string, tofile string) {
	from, err := os.Open(fromfile)
	if err != nil {
		panic(err)
	}
	defer from.Close()

	to, err := os.OpenFile(tofile, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	defer to.Close()

	_, err = io.Copy(to, from)
	if err != nil {
		panic(err)
	}
	//Make sure the to file is actually fully written to disk
	to.Sync()
}

func PrependToFile(prependData []byte, targetFile string, newOutputFile string) {
	if targetFile == newOutputFile {
		panic("targetFile and newOutputFile cannot be the same")
	}

	// Open the target file for reading
	f, err := os.Open(targetFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Read the content of the target file into a buffer
	var buf bytes.Buffer
	// Prepend the byte array to the buffer
	buf.Write(prependData)
	// Read the file into the buffer
	_, err = buf.ReadFrom(f)
	if err != nil {
		panic(err)
	}

	// Create a new file to write the result to
	g, err := os.Create(newOutputFile)
	if err != nil {
		panic(err)
	}
	defer g.Close()

	// Write the buffer to the new file
	_, err = buf.WriteTo(g)
	if err != nil {
		panic(err)
	}
}

func TrimLastChar(s string) string {
    r, size := utf8.DecodeLastRuneInString(s)
    if r == utf8.RuneError && (size == 0 || size == 1) {
        size = 0
    }
    return s[:len(s)-size]
}

func TrimFirstChar(s string) string {
    _, i := utf8.DecodeRuneInString(s)
    return s[i:]
}

func ExportsFromFile(file string) ([]string, error) {
	var exports []string
	pe, err := peparser.New(file, &peparser.Options{})
	if err != nil {
		return exports, err
    }
    err = pe.Parse()
    if err != nil {
        return exports, err
    }
	for _,v := range pe.Export.Functions {
		if v.Name != "Run" {
			exports = append(exports, v.Name)
		}
	}
	return exports, err
}

func BuildCStyleByteArray(raw_bytes []byte) string {
	//Build C style hexstring of shellcode for template
    output := "{"
    for i := 0; i < len(raw_bytes); i++ {
		var hex_byte []byte
		hex_byte = append(hex_byte, raw_bytes[i])
		output += "0x"+hex.EncodeToString(hex_byte)+","
    }
    output = TrimLastChar(output)
    output += "}"
	return output
}

func BuildCStyleByteArrayNoData(raw_bytes []byte) string {
	//Build C style hexstring of shellcode for template
    output := "{"
    for i := 0; i < len(raw_bytes); i++ {
		var hex_byte []byte
		hex_byte = append(hex_byte, raw_bytes[i])
		output += "NODATA(0x"+hex.EncodeToString(hex_byte)+"),"
    }
    output = TrimLastChar(output)
    output += "}"
	return output
}

func AntiCommandInject(input []string) {
	for _, v := range input {
	//No funny business command injection - alphanumeric filenames only
		is_alphanumeric := regexp.MustCompile(`^[a-zA-Z0-9_/\.]*$`).MatchString(v)
		if !is_alphanumeric {
			fmt.Println("No funny business - alphanumeric values only (and _ / .) for string: "+v)
			os.Exit(1)
		}
	}
}

func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func TypeAssertionValidator(input interface{}) string {
	switch input.(type) {
		case string:
			return "string"
		case int:
			return "int"
		case bool:
			return "bool"
		default:
		  return "unknown"
	  }
}

func GetSyscallBytes (filepath string, functions []string) []SyscallStruct {
	var output []SyscallStruct
	pe, err := peparser.New(filepath, &peparser.Options{})
	if err != nil {
		fmt.Printf("Error while opening file: %s, reason: %v\n", filepath, err)
		os.Exit(1)
	}
	err = pe.Parse()
	if err != nil {
		fmt.Printf("Error while parsing file: %s, reason: %v\n", filepath, err)
		os.Exit(1)
	}
	for _, func_name := range functions {
		syscall_struct := new(SyscallStruct)
		syscall_struct.FunctionName = func_name
		
		djb2_byetarray := make([]byte, 4)
		binary.LittleEndian.PutUint32(djb2_byetarray, uint32(djb2Hash(func_name)))
		syscall_struct.Djb2Name = make([]byte, 4)
		copy(syscall_struct.Djb2Name, djb2_byetarray)
		syscall_struct.RawOffset = 0
		syscall_struct.FunctionBytes = make([]byte,8)
		syscall_struct.SyscallId = make([]byte,4)
		var raw_offset uint32 = 0
		for _,v := range pe.Export.Functions {
			if v.Name == func_name {
				exp_rva := v.FunctionRVA
				for _, sec := range pe.Sections {
					if sec.Header.VirtualAddress + sec.Header.SizeOfRawData >= exp_rva {
						raw_offset = exp_rva - sec.Header.VirtualAddress + sec.Header.PointerToRawData
						syscall_struct.RawOffset = raw_offset
						break
					}
				}
				if syscall_struct.RawOffset == 0 {
					fmt.Printf("Failed to get raw offset for %s\n",syscall_struct.FunctionName)
					os.Exit(1)
				}
				output = append(output, *syscall_struct)
			}
		}
	}
	return output
}

func ExtractSyscallIds(edr_name string, ntdll_path string) []SyscallStruct {
	//Parse function name list
	var readFile *os.File
	var err error
	readFile, err = os.Open("_lib/"+edr_name+"_hooks.txt")
	if err != nil {
		fmt.Println("[-] Error opening _lib/"+edr_name+"_hooks")
		os.Exit(1)
	}

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	var hooked_funcs []string
	for fileScanner.Scan() {
		hooked_funcs = append(hooked_funcs, fileScanner.Text())
	}
	readFile.Close()
	// Get actual bytes from function entry on disk
	syscalls := GetSyscallBytes(ntdll_path, hooked_funcs)
	v, err := os.ReadFile(ntdll_path) 
	if err != nil {
		fmt.Println("[-] Error opening _lib/ntdll.dll")
		os.Exit(1)
	}
	for i,item  := range syscalls {
		if item.RawOffset == 0 {
			fmt.Printf("[-] Extracting raw offset failed for %s\n", item.FunctionName)
			os.Exit(1)
		} else {
			copy(syscalls[i].FunctionBytes, v[item.RawOffset:item.RawOffset+8])
			if bytes.Equal(syscalls[i].FunctionBytes[0:4], []byte{0x4c, 0x8b, 0xd1, 0xb8}) {
				copy(syscalls[i].SyscallId, item.FunctionBytes[4:8])
			} else {
				fmt.Printf("[-] Extracting syscall bytes failed for %s\n", item.FunctionName)
				os.Exit(1)
			}
			if syscalls[i].SyscallId[0] == 0 {
				fmt.Printf("[-] Extracting syscall id failed for %s\n", item.FunctionName)
				os.Exit(1)
			}
		}
	}
	return syscalls
}