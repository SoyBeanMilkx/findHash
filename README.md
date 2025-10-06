# findHash
[findhash](https://github.com/Pr0214/findhash) for ARM64 (An IDA script that can detect hash algorithms such as MD5 or SHA)

## Improvements：

1. **Support ARM64**
2. **Support IDA7.0 - IDA9.1**
3. **Intelligent False Positive Filtering**
4. **Precise String Matching**



##  Installation：

1. Copy 

   ```bash
   findHash.py
   findHash.xml
   ```

    to IDA's 

   ```
   ../yourIDA/plugins
   ```

2. Restart IDA Pro



## Usage

1. Load an ARM32 or ARM64 binary in IDA Pro
2. Run the plugin:
   - Menu: `Edit` → `Plugins` → `findHash`
3. Check the output window for results
4. If suspicious functions found, use the generated Frida script:

```bash
   frida -UF -l /path/to/generated_script.js
```



## Configuration

#### Add Custom Signatures

Edit `findHash.xml` to add custom hash algorithm signatures:

xml

```xml
<p t="Your Algorithm Name [bits.size]">HEX_SIGNATURE</p>
```

#### Modify Filtering Rules

Edit blacklists in `findHash.py`:

python

```python
# Filter encryption algorithms
encryption_blacklist = ['des', 'aes', 'rc4', ...]

# Filter C++ stdlib
stdlib_namespaces = ['std::', '__ndk1::', ...]
```



#### Credits

- [findhash](https://github.com/Pr0214/findhash)
