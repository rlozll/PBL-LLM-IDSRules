// src/components/CtiList.js
import React from 'react';
import './CtiList.css';

function CtiList() {
  // 실제 데이터가 아직 없다면, 임시 데이터 사용
  const ctiItems = [
    {
    title: "AgentTesla SMTP Credential Leak 탐지",
    site: "malwarebazaar.com",
    date: "2025-11-08",
  },
  {
    title: "FakeUpdate phishing redirection 탐지 (가짜 브라우저 업데이트 유도)",
    site: "threatfox.abuse.ch",
    date: "2025-10-29",
  },
  {
    title: "RedLine Stealer outbound connection 차단",
    site: "anyrun.net",
    date: "2025-10-10",
  },
  {
    title: "Cobalt Strike Beacon activity detected in internal network",
    site: "virustotal.com",
    date: "2025-09-24",
  },
  {
    title: "Emotet mail spam campaign 감염 시도",
    site: "urlhaus.abuse.ch",
    date: "2025-09-12",
  },
  {
    title: "AsyncRAT C2 traffic observed (비정상 도메인 통신 탐지)",
    site: "abuseipdb.com",
    date: "2025-08-30",
  },
  {
    title: "PowerShell obfuscated payload execution (명령 실행 시도)",
    site: "tria.ge",
    date: "2024-12-18",
  },
  {
    title: "QakBot infection chain via Excel macro 탐지",
    site: "broadcom.com",
    date: "2024-11-05",
  },
  {
    title: "Log4Shell exploit attempt (JNDI RCE) 탐지",
    site: "cve.mitre.org",
    date: "2023-12-28",
  },
  {
    title: "Formbook C2 beacon pattern 탐지",
    site: "malpedia.caad.fkie.fraunhofer.de",
    date: "2023-07-10",
  },
  ];

  return (
    <div className="cti-list-container">
      <header className="cti-header">
        <h1>CTI Lists </h1>
        <p className="subtitle">Check out the latest CTIs</p>
      </header>

      <div className="cti-table">
        <div className="cti-table-header">
          <div className="cti-col-title">Post Titles</div>
          <div className="cti-col-site">Site Names</div>
          <div className="cti-col-date">Date</div>
        </div>

        <div className="cti-table-body">
          {ctiItems.map((item) => (
            <div className="cti-row" key={item.id}>
              <div className="cti-col-title">{item.title}</div>
              <div className="cti-col-site">{item.site}</div>
              <div className="cti-col-date">{item.date}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default CtiList;