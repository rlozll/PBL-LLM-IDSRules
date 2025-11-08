// src/components/CtiList.js
import React from 'react';
import './CtiList.css';

function CtiList() {
  // 실제 데이터가 아직 없다면, 임시 데이터 사용
  const ctiItems = [
    { id: 1, title: '게시글 올라온 거 대충 제목 정도...', site: '무슨 사이트인지', date: 'July 1, 2024' },
    { id: 2, title: '게시글 올라온 거 대충 제목 정도...', site: '무슨 사이트인지', date: 'July 25, 2024' },
    { id: 3, title: '게시글 올라온 거 대충 제목 정도...', site: '무슨 사이트인지', date: 'August 1, 2024' },
    { id: 4, title: '게시글 올라온 거 대충 제목 정도...', site: '무슨 사이트인지', date: 'August 22, 2024' },
    { id: 5, title: '게시글 올라온 거 대충 제목 정도...', site: '무슨 사이트인지', date: 'August 29, 2024' },
    { id: 6, title: '게시글 올라온 거 대충 제목 정도...', site: '무슨 사이트인지', date: 'September 5, 2024' },
  ];

  return (
    <div className="cti-list-container">
      <header className="cti-header">
        <h1>CTI Lists</h1>
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