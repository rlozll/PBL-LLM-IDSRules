// src/components/History.js
import React from "react";
import "./History.css";

const History = ({ setCurrentView }) => {
  const historyData = [
    {
      title: "SolarMarker 백도어 탐지 (HTTP exfiltration)",
      date: "2025.10.22",
      rule: "alert http any any -> any any (msg:\"SolarMarker data exfiltration\"; content:\"solarmarker\"; sid:100020; rev:1;)",
    },
    {
      title: "AgentTesla SMTP 데이터 유출 시도",
      date: "2025.08.30",
      rule: "alert tcp any any -> any 587 (msg:\"AgentTesla SMTP exfiltration attempt\"; content:\"MAIL FROM:\"; sid:100019; rev:1;)",
    },
    {
      title: "FakeUpdate 피싱 사이트 접근 탐지",
      date: "2025.05.12",
      rule: "alert http any any -> any any (msg:\"FakeUpdate phishing site access\"; content:\"fakeupdate\"; sid:100018; rev:1;)",
    },
    {
      title: "RedLine Stealer C2 통신 차단",
      date: "2024.11.05",
      rule: "alert ip any any -> 185.44.82.11 any (msg:\"RedLine Stealer C2 communication\"; sid:100017; rev:1;)",
    },
    {
      title: "Cobalt Strike Beacon 패턴 탐지",
      date: "2024.09.28",
      rule: "alert tcp any any -> any 443 (msg:\"Cobalt Strike beacon pattern\"; flow:established,to_server; content:\"MZ\"; sid:100016; rev:1;)",
    },
    {
      title: "Emotet 스팸 메일 첨부 링크 차단",
      date: "2024.07.14",
      rule: "alert smtp any any -> any any (msg:\"Emotet spam email link\"; content:\"http://\"; sid:100015; rev:1;)",
    },
    {
      title: "CVE-2024-55321 취약점 익스플로잇 탐지",
      date: "2024.03.03",
      rule: "alert tcp any any -> any 80 (msg:\"CVE-2024-55321 exploit attempt\"; content:\"/vulnerable/path\"; sid:100014; rev:1;)",
    },
    {
      title: "PowerShell 인코딩 명령 실행 탐지",
      date: "2023.12.22",
      rule: "alert process any any (msg:\"PowerShell base64 encoded command\"; content:\"-encodedcommand\"; sid:100013; rev:1;)",
    },
    {
      title: "정보탈취형 악성코드 업로드 시도 탐지",
      date: "2023.11.10",
      rule: "alert http any any -> any any (msg:\"Infostealer upload attempt\"; content:\"/upload.php\"; sid:100012; rev:1;)",
    },
    {
      title: "AsyncRAT 비콘 통신 도메인 탐지",
      date: "2023.08.02",
      rule: "alert dns any any -> any any (msg:\"AsyncRAT beacon domain\"; content:\"asyncconnect\"; sid:100011; rev:1;)",
    },
    {
      title: "Microsoft Exchange SSRF 공격 시도",
      date: "2023.04.17",
      rule: "alert http any any -> any 443 (msg:\"Exchange SSRF attempt\"; content:\"/ecp/proxyLogon.ecp\"; sid:100010; rev:1;)",
    },
    {
      title: "Log4Shell 원격 코드 실행 탐지",
      date: "2023.01.05",
      rule: "alert tcp any any -> any any (msg:\"Log4Shell exploit attempt\"; content:\"${jndi:ldap://\"; sid:100009; rev:1;)",
    },
  ];

  // 날짜 기준 내림차순 정렬 (최신순)
  const sortedHistory = [...historyData].sort((a, b) => {
    const dateA = new Date(a.date.replace(/\./g, "/"));
    const dateB = new Date(b.date.replace(/\./g, "/"));
    return dateB - dateA;
  });

  // 클릭 시 Dashboard(HomeView)로 이동하는 함수
  const handleRowClick = () => {
    setCurrentView("main"); // App.js의 currentView를 'main'으로 변경
  };

  return (
    <div className="history-container">
      <div className="history-header">
        <h1>History</h1>
        <p className="subtitle">Look at past records</p>
      </div>

      <div className="history-table">
        <div className="history-table-header">
          <div>분석 제목 (Title)</div>
          <div>생성된 Rule</div>
          <div>Date</div>
        </div>

        <div className="history-table-body">
          {sortedHistory.map((item, idx) => (
            <div
              className="history-row"
              key={idx}
              onClick={handleRowClick}
              style={{ cursor: "pointer" }}
            >
              <div className="col-title">{item.title}</div>
              <div className="col-rule">{item.rule}</div>
              <div className="col-date">{item.date}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default History;