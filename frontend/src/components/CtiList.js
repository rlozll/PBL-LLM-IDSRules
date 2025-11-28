// src/components/CtiList.js
import React, { useState, useEffect } from 'react'; // useState, useEffect 임포트
import './CtiList.css';
import { getNewCtiList } from '../api'; // api.js에서 함수 가져오기
import { ReactComponent as LinkCopyIcon } from './icons/Copy.svg';


const getLastReadTime = (site) => {
  return localStorage.getItem(`cti_last_read_${site}`) || null;};
const updateLastReadTime = (site) => {
  localStorage.setItem(`cti_last_read_${site}`, new Date().toISOString()); };

const RSS_SITE_NAMES = [
  "NVD Analyzed", "Cloudflare Blog", "CISA Alerts", "CERT-KR",
  "Mandiant (Google)", "Palo Alto (Unit 42)", "CrowdStrike", "Microsoft Security",
  "Rapid7 (AttackerKB)", "The Hacker News", "Krebs on Security", "Bleeping Computer", "Schneier on Security",];



function CtiList({ setCurrentView, setUrl }) { // (setCurrentView는 Bookmarked Pages용으로 남겨둘 수 있음)
  
  // --- ▼▼▼ 가짜 데이터 대신, DB에서 가져올 데이터 상태 추가 ▼▼▼ ---
  const [ctiItems, setCtiItems] = useState([]); // 빈 배열로 초기화
  const [isLoading, setIsLoading] = useState(true); // 로딩 상태
  const [error, setError] = useState('');
  
  // --- ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲ ---

  const [copyMessage, setCopyMessage] = useState({ visible: false, text: '' })
  const [selectedSite, setSelectedSite] = useState(null);

  // --- ▼▼▼ 컴포넌트가 로드될 때 API를 호출하여 DB 데이터 가져오기 ▼▼▼ ---
  useEffect(() => {
    const fetchList = async () => {
      setIsLoading(true);
      setError('');
      try {
        const items = await getNewCtiList(); // 백엔드 /api/new_cti_list 호출
        setCtiItems(items); // 성공 시 상태 업데이트
      } catch (err) {
        console.error("CTI List 로딩 실패:", err);
        setError("CTI 목록을 불러오는 데 실패했습니다.");
      }
      setIsLoading(false);
    };
    fetchList();
  }, []); // [] : 컴포넌트가 처음 렌더링될 때 1회만 실행
  // --- ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲ ---

  // --- ▼▼▼ 디자인 시안의 요구사항 구현 (새 탭에서 링크 열기) ▼▼▼ ---
  const handleRowClick = (e, link) => {
    // 클릭 시 원본 CTI 사이트로 새 탭에서 이동
    e.preventDefault();
    window.open(link, '_blank', 'noopener,noreferrer');
  };
  // --- ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲ ---

  const showCopyToast = (message) => {
    setCopyMessage({ visible: true, text: message });

    setTimeout(() => {
      setCopyMessage({ visible: false, text: '' });
    }, 2500);
  };

  const handleCopyLink = (e, link) => {
    e.stopPropagation();
    e.preventDefault();

    navigator.clipboard.writeText(link)
      .then(() => {
        showCopyToast('링크 복사 완료');

        if (setUrl) {
          setUrl(link);
        }
      })
      .catch(err => {
        console.error('링크 복사 실패:', err);
        showCopyToast('링크 복사 실패');
      });
  };

  // 사이트 업데이트 표시
  const siteHasUpdate = (site) => {
    const lastRead = getLastReadTime(site);
    if (!lastRead) return true; 

    const lastReadTime = new Date(lastRead);

    return ctiItems.some(
      (item) =>
        item.site_name === site &&
        item.published_date &&                       // ✅ 날짜 있는 애만 비교
        new Date(item.published_date) > lastReadTime
    );
  };

    // 선택된 사이트에 따라 목록 필터링
  const filteredItems = selectedSite
    ? ctiItems.filter(item => item.site_name === selectedSite)
    : ctiItems;
  
  return (
    <div className="cti-list-container">
      {copyMessage.visible && (
        <div className="copy-toast-message">
          {copyMessage.text}
        </div>
      )}

      <header className="cti-header">
        <h1>CTI Lists</h1>
        <p className="subtitle"> 최신 CTI 피드를 확인하세요 </p>
        <div className="site-filter-bar">
          {RSS_SITE_NAMES.map((name) => (
            <span
              key={name}
              className={
                "site-filter-text" +
                (selectedSite === name ? " active" : "")
              }
              onClick={() => {
                if (selectedSite === name) {
                  setSelectedSite(null); // 전체보기
                } else {
                  setSelectedSite(name);
                  updateLastReadTime(name);   // 읽음 처리
                }
              }}
            >
              {name}
               {siteHasUpdate(name) && (
                  <span className="site-update-dot" />
               )}
            </span>
          ))}
        </div>
      </header>

      <div className="cti-table">
        <div className="cti-table-header">
          <div className="cti-col-title">Title</div>
          <div className="cti-col-site">Site</div>
          <div className="cti-col-date">Date</div>
        </div>

        <div className="cti-table-body">
          {isLoading && <p style={{textAlign: "center", padding: "20px"}}>Loading...</p>}
          {error && <p style={{textAlign: "center", padding: "20px", color: "red"}}>{error}</p>}
          
          {!isLoading && filteredItems.length === 0 && (
            <p style={{ textAlign: "center", padding: "20px" }}>
              {selectedSite
                ? `해당 사이트에서 수집된 CTI가 아직 없습니다.`
                : '새로운 CTI 정보가 없습니다. (백그라운드에서 `scripts/rss_collector.py`를 실행했는지 확인하세요.)'}
            </p>
          )}

          {filteredItems.map((item, idx) => (
            <div
              key={item.id || idx} // DB의 id 사용
              className="cti-row"
              onClick={(e) => handleRowClick(e, item.link)} // 박스 클릭 -> 새 탭
              title={`새 탭에서 원본 글 보기: ${item.title}`}
              style={{ cursor: 'pointer' }}
            >
              <div className="cti-col-title">{item.title}</div>
              <div className="cti-col-site">{item.site_name}</div>
              <div className="cti-col-date">
                <span className="date-text">
                {/* 날짜 형식 간단하게 변환 */}
                {item.published_date ? new Date(item.published_date).toLocaleDateString() : 'N/A'}
                </span>

                <button
                  className = "copy-button"
                  onClick={(e) => handleCopyLink(e, item.link)}
                  title="URL 복사"
                  aria-label="Copy Link"
                >
                  <LinkCopyIcon className="copy-icon" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}


export default CtiList;