package main

import (
	"AST/apocrypha/modules/apocrypha"
	"fmt"
	"io/ioutil"
	"os"
	"github.com/akamensky/argparse"
	"gopkg.in/yaml.v2"
	"strings"
)

func main() {
	logo := `

    ░█████╗░██████╗░░█████╗░░█████╗░██████╗░██╗░░░██╗██████╗░██╗░░██╗░█████╗░
    ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗╚██╗░██╔╝██╔══██╗██║░░██║██╔══██╗
    ███████║██████╔╝██║░░██║██║░░╚═╝██████╔╝░╚████╔╝░██████╔╝███████║███████║
    ██╔══██║██╔═══╝░██║░░██║██║░░██╗██╔══██╗░░╚██╔╝░░██╔═══╝░██╔══██║██╔══██║
    ██║░░██║██║░░░░░╚█████╔╝╚█████╔╝██║░░██║░░░██║░░░██║░░░░░██║░░██║██║░░██║
    ╚═╝░░╚═╝╚═╝░░░░░░╚════╝░░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░╚═╝░░╚═╝╚═╝░░╚═╝

    `
	fmt.Print(logo + "\n\n")
	parser := argparse.NewParser("Apocrypha", "that which speaks in the wastes")
	config_yaml := parser.String("c", "config_yaml", &argparse.Options{Required: true, Help: "Filepath to the config file"})

	err := parser.Parse(os.Args)
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

	// Read YAML config file into 'data'
	data, err := ioutil.ReadFile(*config_yaml)
	if err != nil {
		panic(err)
	}

	// Unmarshal yaml from 'data' to 'config'
	var config apocrypha.YamlConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		panic(err)
	}

	// Validate required yaml
	if config.Mode == "" {
		fmt.Println("[-] Must select a mode - 'shellcode' or 'wrapper'.")
		os.Exit(1)
	}
	if config.InFile == "" {
		fmt.Println("[-] Must define an input file (in_file).")
		os.Exit(1)
	}
	if config.OutFilename == "" {
		fmt.Println("[-] Must define an output filename (out_filename).")
		os.Exit(1)
	}
	// Normalize case on certain arguments
	config.Mode = strings.ToLower(config.Mode)

	if config.Mode == "wrapper" {
		if config.WrapperOpts.Format == "" {
			fmt.Println("[-] Must define a format (wrapper_opts.format).")
			os.Exit(1)
		} else {
			config.WrapperOpts.Format = strings.ToLower(config.WrapperOpts.Format)
		}
	}
	if config.ShellcodeOpts.EdrHooks != "" {
		// Normalize case on certain arguments
		config.ShellcodeOpts.EdrHooks = strings.ToLower(config.ShellcodeOpts.EdrHooks)
		if config.ShellcodeOpts.EdrHooks != "stomp" {
			fmt.Println("[-] Invalid edr_hooks choice. Valid choices: ['stomp']")
			os.Exit(1)
		}
	}
	if config.ShellcodeOpts.EdrTool != "" {
		// Normalize case on certain arguments
		config.ShellcodeOpts.EdrTool = strings.ToLower(config.ShellcodeOpts.EdrTool)
		if config.ShellcodeOpts.EdrTool != "crowdstrike" && config.ShellcodeOpts.EdrTool != "cylance" && config.ShellcodeOpts.EdrTool != "sentinelone" {
			fmt.Println("[-] Invalid edr_tool choice. Valid choices: ['crowdstrike', 'sentinelone','cylance']")
			os.Exit(1)
		}
	}
	if config.Encrypt != "" {
		// Normalize case on certain arguments
		config.Encrypt = strings.ToLower(config.Encrypt)
		if config.Encrypt != "xor" {
			fmt.Println("[-] Invalid encrypt choice. Valid choices: ['xor']")
			os.Exit(1)
		}
	}
	// Off we go - First cleanup any old files from output
	var meta_data map[string]interface{}
	apocrypha.CleanupOutputDir(config, meta_data, true)
	if config.Mode == "shellcode" {
		// Compile and link all PIC files together
		apocrypha.CreateShellcode(config)
		// Encrypt shellcode
		if config.Encrypt == "xor" {
			apocrypha.XorEncrypt(config.OutFilename)
			apocrypha.TemplateXORPrelude(config)
			apocrypha.CompileXORPrelude(config)
		}
	} else if config.Mode == "wrapper" {
		// Copy the original file into ./output/wrapme.bin
		apocrypha.FileCopy(config.InFile, "./output/wrapme.bin")
		//Update config to point to this copied file
		config.InFile = "./output/wrapme.bin"
		// If it's someone else's unencrypted shellcode (like Cobaltstrike Beacon) you may want to encrypt it and prepend xorprelude it before wrapping
		if config.Encrypt == "xor" {
			// Rename the input file to match the filenames used in shellcode mode
			err = os.Rename(config.InFile, "./output/"+config.OutFilename+".bin")
			if err != nil {
				panic(err)
			}
			apocrypha.XorEncrypt(config.OutFilename)
			apocrypha.TemplateXORPrelude(config)
			apocrypha.CompileXORPrelude(config)
			// Restore original name
			err = os.Rename("./output/"+config.OutFilename+".bin", config.InFile)
			if err != nil {
				panic(err)
			}
		}
		meta_data = apocrypha.WrapperTemplater(config)
		apocrypha.WrapperCompiler(config, meta_data)
	} else {
		fmt.Println("Invalid mode. Please choose 'shellcode' or 'wrapper'.")
		os.Exit(1)
	}
	// If debug flag not set, then cleanup ./output/
	if !config.Debug {
		apocrypha.CleanupOutputDir(config, meta_data, false)
	}
	fmt.Println("")
}
