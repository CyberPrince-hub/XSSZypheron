# XSSZypheron - Advanced XSS Detection Tool
A simple, fast and efficient XSS vulnerability scanner for security researchers and penetration testers.

<img width="1253" height="654" alt="xss" src="https://github.com/user-attachments/assets/eea5484a-ae73-4d15-aa10-35d669ccc786" />


## Features

- 🚀 **Fast Multi-threaded Scanning**
- 🎯 **Multiple XSS Payload Types**
- 📁 **Custom Payload Support**
- 🌐 **URL & Form Parameter Testing**
- 📊 **Detailed Reporting**
- 🔧 **Easy to Use**

## 📦 Installation

```bash
git clone https://github.com/CyberPrince-hub/XSSpy.git
cd XSSpy
pip install -r requirements.txt
```

<img width="1053" height="642" alt="xss2" src="https://github.com/user-attachments/assets/ad1d450e-3629-4f4f-9579-e996ef09a9b4" />


## 🚀 Usage

### Scan a Single URL

```bash
python xsspy.py -u "https://example.com/search?q=test"
```

### Scan Multiple URLs

```bash
python xsspy.py -f urls.txt
```

### Use Custom Payloads

```bash
python xsspy.py -u "https://example.com/search?q=test" -p payloads.txt
```

### Save Results

```bash
python xsspy.py -u "https://example.com/search?q=test" -o results.txt
```

### Show Help

```bash
python xsspy.py -h
```

## 📌 Example

```bash
python xsspy.py -u "https://testphp.vulnweb.com/listproducts.php?cat=1"
```

## ⚙️ Command-Line Options

| Option | Description |
|--------|-------------|
| `-u` | Scan a single URL |
| `-f` | Scan URLs from a file |
| `-p` | Load custom XSS payloads |
| `-o` | Save scan results to a file |
| `-t` | Set the number of scanning threads |
| `-h` | Display the help message |

## ⚠️ Disclaimer

This tool is intended only for authorized security testing, penetration testing, and educational purposes. Always obtain explicit permission before testing any website or application. The author is not responsible for any misuse of this tool.

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

