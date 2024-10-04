## 프로그램 동작 예시  
- **메인 화면**  
![image](https://github.com/user-attachments/assets/c1032c01-30ad-4287-b919-02e712eef18a)

- **IP Scan**   
![image](https://github.com/user-attachments/assets/05f8ca60-c31d-4af2-a791-142ef3b4d12e)
![image](https://github.com/user-attachments/assets/79836e2b-d367-4a52-b9bd-c9df1acc7ee7)

- **Port Scan**  
![image](https://github.com/user-attachments/assets/4d59b403-d5bb-4786-9dfd-c9ca233e62b2)
![image](https://github.com/user-attachments/assets/214b88f5-a082-4ec0-be40-2506bdbf4676)

- **Banner Grabbing**     
![image](https://github.com/user-attachments/assets/209a895c-dc33-483b-bde1-97fb9841b44f)
![image](https://github.com/user-attachments/assets/82c1d75d-6eb5-4700-88db-d1620502ce97)

- **UDP Flooding**   
![image](https://github.com/user-attachments/assets/e1779a0f-ec5c-464b-92ff-a98028d5649e)


 

## 기능별 동작 순서  
- **Scan 기능**    
![image](https://github.com/user-attachments/assets/a7b6c705-0afc-49fd-94f0-c778de8dae0c)



- **DoS 공격 기능**    
![image](https://github.com/user-attachments/assets/52399866-bbba-48a7-94ff-046cbd092fa9)



## 프로그램 기능 요약
- 크게 Scanning 기능과 DoS 공격 기능으로 이루어져 있습니다.
- Scanning 종류는 총 3가지로 IP Scan, Port Scan, Banner Grabbing이 있습니다. Port Scan은 1번부터 1023번까지의 well-known port 활성화 여부를 탐지하며 스캐닝 종류와 open, closed, filtered 판단은 nmap의 기준을 참고하였습니다.
- DoS 공격의 종류는 총 10가지로 UDP Flooding, ICMP Flooding, SYN Flooding, LAND Attack, Teardrop Attack, Slowloris Attack, Rudy Attack, HTTP Method Flooding, Hulk DoS로 이루어져 있습니다.
