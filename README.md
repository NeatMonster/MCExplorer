# MCExplorer

This is a Python portage of the Microcode Explorer plugin created by @[RolfRolles](https://github.com/RolfRolles).

## Disclaimer

Because the Microcode API isn't exported to Python, I had to make extensive use of the `ctypes` module. As a result, the plugin is only compatible with **IDA 7.2** and on **Windows**. You probably have no use for it, sorry.

You might be wondering why I created it though. I simply wanted to play around with Hex-Rays decompiler's micro-code and with the IDA Pro's internals more generally. As such, the plugin can serve as a reference on how to use unexported APIs (I'm thinking of you dispatcher), and to showcase why it is not a bright idea. You have been warned!

Nevertheless, I'm still satisfied with my little experiment and learned a ton of things. Maybe you will too...

## Credits

* Original repository: https://github.com/RolfRolles/HexRaysDeob
* Related blog-post: http://www.hexblog.com/?p=1248
