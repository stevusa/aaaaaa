ATTILA SERBIAN TRAINER - NATIVE C++ / WIN32

Sadrzaj:
- AttilaSerbianTrainerCPP.sln
- AttilaSerbianTrainerCPP.vcxproj
- main.cpp

Ova verzija:
- ne koristi .NET
- ne zahteva Cheat Engine
- ne trazi Attila.dll po imenu
- pronalazi Attila.exe
- AOB skenira izvrsne regione memorije
- napravljena je kao Win32/x86, sto odgovara originalnoj Cheat Engine tabeli

KAKO NAPRAVITI EXE:
1. Instaliraj Visual Studio 2022 sa workload-om:
   "Desktop development with C++"
2. Otvori AttilaSerbianTrainerCPP.sln
3. Gore izaberi:
   Release | x86
4. Build -> Build Solution
5. EXE ce biti u:
   bin\Release\AttilaSerbianTrainer.exe

KORISCENJE:
1. Pokreni Attila: Total War.
2. Pokreni AttilaSerbianTrainer.exe.
3. Klikni "SKENIRAJ AOB POTPISE".
4. Ako su kljucni potpisi UNIQUE, build je verovatno kompatibilan
   sa originalnim potpisima iz CT tabele.

NAPOMENA:
Ovo je dijagnosticka/native osnova trainera. Ne ukljucuje aktivne memory patch
hookove dok se ne potvrde potpisi na korisnikovom build-u igre.
