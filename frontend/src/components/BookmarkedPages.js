import React, { useState, useEffect, useRef } from "react";
import "./BookmarkedPages.css";
import trashIcon from "./icons/Trash2.svg"; // 아이콘 경로는 실제 파일 위치에 맞게 조정하세요
import linkIcon from "./icons/Link3.svg";  // 아이콘 경로는 실제 파일 위치에 맞게 조정하세요

// api.js에서 필요한 함수들을 모두 임포트합니다.
import {
    getBookmarkSites,
    addBookmarkSite,
    getBookmarkResults,
    getBookmarkResultDetail
    // (api.js에 deleteBookmarkSite 함수 구현 필요)
    // deleteBookmarkSite 
} from "../api";

// App.js로부터 탭 이동(setCurrentView)과 결과 주입(setAnalysisResult) 함수를 props로 받습니다.
function BookmarkedPages({ setCurrentView, setAnalysisResult }) {

    // --- 상태(State) 정의 ---
    const [showInput, setShowInput] = useState(null); // URL 입력창 표시 여부 (Link 1~5)
    const [inputValue, setInputValue] = useState("");  // URL 입력값
    const [sortMode, setSortMode] = useState("latest"); // 정렬 모드
    const [deleteTarget, setDeleteTarget] = useState(null); // 삭제 대상 ID
    
    // DB에서 불러올 데이터 상태
    const [bookmarkSites, setBookmarkSites] = useState([]); // 등록된 사이트 (Link 1~5)
    const [bookmarkResults, setBookmarkResults] = useState([]); // 자동 분석된 결과 피드
    const [isLoading, setIsLoading] = useState(true); // 로딩 상태
    const [error, setError] = useState(""); // 에러 메시지

    // --- 데이터 로딩 ---
    // 페이지가 처음 로드될 때 백엔드에서 데이터를 가져옵니다.
    useEffect(() => {
        loadData();
    }, []); // 빈 배열 [] : 컴포넌트 마운트 시 1회만 실행

    const loadData = async () => {
        setIsLoading(true);
        setError("");
        try {
            // 1. 등록된 북마크 사이트 목록 가져오기 (Link 1~5 버튼용)
            const sites = await getBookmarkSites();
            setBookmarkSites(sites || []); // null 방지

            // 2. 자동 분석된 결과 피드 목록 가져오기 (카드 목록용)
            const results = await getBookmarkResults();
            setBookmarkResults(results || []); // null 방지
        } catch (err) {
            console.error("북마크 데이터 로딩 실패:", err);
            setError("데이터를 불러오는 데 실패했습니다.");
        }
        setIsLoading(false);
    };

    // --- 이벤트 핸들러 ---

    // Link 1~5 버튼 클릭 시
    const handleButtonClick = (id) => {
        // 이미 등록된 링크의 URL을 찾아서 입력창에 기본값으로 설정
        const existingSite = bookmarkSites.find(site => site.link_id === id);
        const currentUrl = existingSite ? existingSite.url : "";

        setShowInput(showInput === id ? null : id); // 입력창 토글
        setInputValue(currentUrl); // 입력창에 기존 URL 표시
    };

    // 북마크 URL 추가/수정 (Enter 키 또는 버튼 클릭)
    const handleAddBookmark = async (linkId) => {
        if (!inputValue.trim() || !inputValue.startsWith("http")) {
            alert("http:// 또는 https://로 시작하는 올바른 URL을 입력하세요.");
            return;
        }

        // 5개 제한 확인 (수정은 허용)
        const isEditing = bookmarkSites.some(site => site.link_id === linkId);
        if (!isEditing && bookmarkSites.length >= 5) {
            alert("북마크는 최대 5개까지 등록할 수 있습니다.");
            return;
        }

        // 백엔드 API 호출 (app.py는 이 link_id를 기준으로 INSERT 또는 UPDATE를 수행)
        const response = await addBookmarkSite(inputValue, `Link ${linkId}`, linkId);
        
        if (response && response.status === "success") {
            // 성공 시, DB에서 사이트 목록 즉시 새로고침
            const sites = await getBookmarkSites();
            setBookmarkSites(sites);
            setShowInput(null); // 입력창 닫기
            setInputValue("");
        } else {
            alert(`북마크 추가/수정 실패: ${response.detail || '서버 오류'}`);
        }
    };

    // 카드 클릭 시 (Home 탭으로 상세 결과 이동)
    const handleCardClick = async (recordId) => {
        setIsLoading(true); // 로딩 표시 (선택 사항)
        const detailResult = await getBookmarkResultDetail(recordId);
        
        if (detailResult) {
            // App.js의 상태를 업데이트 (Home 화면이 이 데이터를 표시)
            setAnalysisResult([detailResult]); 
            // Home 탭으로 이동
            setCurrentView('main');
        } else {
            alert("상세 정보를 불러오는 데 실패했습니다.");
            setIsLoading(false);
        }
        // Home 탭으로 이동하면 MainView가 로딩하므로, 여기서는 로딩을 끌 필요 없음
    };

    // 삭제 버튼 클릭 시
    const handleDeleteClick = (e, id) => {
        e.stopPropagation(); // 카드 클릭(Home 이동) 방지
        setDeleteTarget(id);
    };

    const cancelDelete = () => setDeleteTarget(null);

    const confirmDelete = async () => {
        // TODO: api.js에 deleteBookmarkResult(deleteTarget) 함수 구현 및 호출
        // await deleteBookmarkResult(deleteTarget);
        // 삭제 성공 후, 목록 새로고침
        // const results = await getBookmarkResults();
        // setBookmarkResults(results);
        alert(`(구현 필요) ID: ${deleteTarget} 삭제 요청`);
        setDeleteTarget(null);
    };

    // 정렬 로직 (DB에서 가져온 bookmarkResults 기준)
    const sortedBookmarks = [...bookmarkResults].sort((a, b) => {
        const dateA = new Date(a.created_at);
        const dateB = new Date(b.created_at);
        
        if (sortMode === "latest") return dateB - dateA;
        if (sortMode === "oldest") return dateA - dateB;
        if (sortMode === "name") return (a.post_title || "").localeCompare(b.post_title || "");
        return 0;
    });

    // Link 1~5 버튼 (DB 데이터(bookmarkSites) 기반으로 렌더링)
    const linkButtons = [
        { id: 1, name: "Link 1", class: "link-1" },
        { id: 2, name: "Link 2", class: "link-2" },
        { id: 3, name: "Link 3", class: "link-3" },
        { id: 4, name: "Link 4", class: "link-4" },
        { id: 5, name: "Link 5", class: "link-5" },
    ];
    
    const renderedLinkButtons = linkButtons.map(btn => {
        const foundSite = bookmarkSites.find(site => site.link_id === btn.id);
        let displayName = btn.name;
        let isSet = false;
        let fullUrl = ""; // title 속성용
        
        if (foundSite) {
            isSet = true;
            fullUrl = foundSite.url;
            try {
                // 등록된 URL의 도메인을 이름으로 표시
                const domain = new URL(foundSite.url).hostname.replace("www.", "");
                displayName = domain.length > 15 ? `${domain.substring(0, 12)}...` : domain;
            } catch {
                displayName = "Invalid URL";
            }
        }
        return { ...btn, name: displayName, isSet: isSet, fullUrl: fullUrl };
    });

    return (
        <div className="bookmark-container">
            <h1 className="bookmark-header">Bookmarked Pages</h1>

            {/* 링크 버튼 */}
            <div className="link-buttons">
                {renderedLinkButtons.map((btn) => (
                    <div key={btn.id} style={{ position: "relative" }}>
                        <button
                            className={`link-btn ${btn.class} ${btn.isSet ? 'set' : ''}`} // 'set' 클래스로 등록 여부 표시
                            onClick={() => handleButtonClick(btn.id)}
                            title={btn.isSet ? `Edit: ${btn.fullUrl}` : `Link ${btn.id} 등록하기`}
                        >
                            {btn.name}
                        </button>

                        {showInput === btn.id && (
                            <div className="bubble-input">
                                <input
                                    type="text"
                                    placeholder="https://... URL 입력"
                                    value={inputValue}
                                    onChange={(e) => setInputValue(e.target.value)}
                                    onKeyDown={(e) => {
                                        if (e.key === "Enter") handleAddBookmark(btn.id);
                                    }}
                                />
                                <button
                                    onClick={() => handleAddBookmark(btn.id)}
                                    className="add-url-btn"
                                >
                                    <img src={linkIcon} alt="add" />
                                </button>
                            </div>
                        )}
                    </div>
                ))}
            </div>

            {/* 정렬 토글 */}
            <div className="sort-toggle">
                <button
                    className={sortMode === "latest" ? "active" : ""}
                    onClick={() => setSortMode("latest")}
                >
                    최신순
                </button>
                <button
                    className={sortMode === "oldest" ? "active" : ""}
                    onClick={() => setSortMode("oldest")}
                >
                    오래된순
                </button>
                <button
                    className={sortMode === "name" ? "active" : ""}
                    onClick={() => setSortMode("name")}
                >
                    이름순
                </button>
            </div>

            {/* 카드 목록 */}
            <div className="bookmark-grid">
                {isLoading && <p>Loading results...</p>}
                {error && <p className="error-message">{error}</p>}
                {!isLoading && sortedBookmarks.length === 0 && (
                    <p>자동 분석된 북마크 결과가 없습니다.</p>
                )}
                
                {sortedBookmarks.map((b) => (
                    <div 
                        key={b.id} 
                        className="bookmark-card" 
                        onClick={() => handleCardClick(b.id)}
                        title="클릭하여 상세 분석 결과 보기"
                    >
                        {/* b.site_id (DB에 저장된 link_id)를 기반으로 
                          해당 Link 버튼의 클래스(link-1, link-2 등)를 찾아서 태그 스타일링
                        */}
                        <div className={`bookmark-tag ${linkButtons.find(btn => btn.id === b.site_id)?.class || 'link-1'}`}>
                           {linkButtons.find(btn => btn.id === b.site_id)?.name || 'Link'}
                        </div>
                        
                        <div className="bookmark-title">
                            <a 
                                href={b.post_url} 
                                target="_blank" 
                                rel="noopener noreferrer"
                                onClick={(e) => e.stopPropagation()} // 카드 클릭(Home 이동) 방지
                                title={`새 탭에서 원본 글 보기: ${b.post_url}`}
                            >
                                {b.post_title || b.post_url}
                            </a>
                        </div>

                        <div className="bookmark-desc">
                            {/* 생성된 Rule 요약 표시 (예: msg 부분만) */}
                            {b.generated_rule ? (b.generated_rule.split('msg:"')[1]?.split('";')[0] || b.generated_rule) : "분석 실패 또는 진행 중..."}
                        </div>

                        <div className="bookmark-footer">
                            <img
                                src={trashIcon}
                                alt="delete"
                                className="trash-icon"
                                onClick={(e) => handleDeleteClick(e, b.id)}
                            />
                            <span className="bookmark-date">{new Date(b.created_at).toLocaleString('ko-KR')}</span>
                        </div>
                    </div>
                ))}
            </div>

            {/* 삭제 확인 팝업 */}
            {deleteTarget && (
                <div className="delete-modal">
                    <div className="delete-box">
                        <p>정말 삭제하시겠습니까?</p>
                        <div className="delete-buttons">
                            <button className="cancel-btn" onClick={cancelDelete}>취소</button>
                            <button className="delete-btn" onClick={confirmDelete}>삭제</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

export default BookmarkedPages;