xor_function = """
    int count = 0;
    int i;
    for (i=0;i<sizeof(shellcode);i++)
    {
        shellcode[i] = shellcode[i] ^ key[count];
        if (count == sizeof(key)-1)
        {
            count = 0;
        }
        else
        {
            count = count + 1;
        }
    }
    """