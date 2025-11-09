import React, { useState, useEffect } from "react";
import "./BookmarkList.css";
import trashIcon from "./icons/Trash2.svg?update"; 
import linkIcon from "./icons/Link3.svg";

function BookmarkList() {
  const linkButtons = [
    { id: 1, name: "Link 1", class: "link-1" },
    { id: 2, name: "Link 2", class: "link-2" },
    { id: 3, name: "Link 3", class: "link-3" },
    { id: 4, name: "Link 4", class: "link-4" },
    { id: 5, name: "Link 5", class: "link-5" },
  ];

  const [showInput, setShowInput] = useState(null);
  const [inputValue, setInputValue] = useState("");
  const [bookmarks, setBookmarks] = useState([]);
  const [sortMode, setSortMode] = useState("latest");
  const [deleteTarget, setDeleteTarget] = useState(null);
   const [isLoaded, setIsLoaded] = useState(false);

  //  localStorage 불러오기
  useEffect(() => {
    const saved = localStorage.getItem("bookmarks");
    if (saved) {
      setBookmarks(JSON.parse(saved));
    }
    setIsLoaded(true); // 데이터 로딩 완료 표시
  }, []);

  //  localStorage 저장
  useEffect(() => {
    if (isLoaded) {
      localStorage.setItem("bookmarks", JSON.stringify(bookmarks));
    }
  }, [bookmarks, isLoaded]);

  const handleButtonClick = (id) => {
    setShowInput(showInput === id ? null : id);
    setInputValue("");
  };

  const getCurrentDateTime = () => {
    const now = new Date();
    const y = now.getFullYear();
    const m = String(now.getMonth() + 1).padStart(2, "0");
    const d = String(now.getDate()).padStart(2, "0");
    const hh = String(now.getHours()).padStart(2, "0");
    const mm = String(now.getMinutes()).padStart(2, "0");
    return `${y}-${m}-${d} ${hh}:${mm}`;
  };

  const handleAddBookmark = (id) => {
    if (!inputValue.trim()) return;
    const newCard = {
      id: Date.now(),
      linkId: id,
      tag: `Link ${id}`, //  태그 표시용
      url: inputValue,
      desc: "",
      date: getCurrentDateTime(),
    };
    setBookmarks((prev) => [newCard, ...prev]);
    setShowInput(null);
    setInputValue("");
  };

  const handleDeleteClick = (id) => setDeleteTarget(id);
  const confirmDelete = () => {
    setBookmarks((prev) => prev.filter((b) => b.id !== deleteTarget));
    setDeleteTarget(null);
  };
  const cancelDelete = () => setDeleteTarget(null);

  const sortedBookmarks = [...bookmarks].sort((a, b) => {
    if (sortMode === "latest") return new Date(b.date) - new Date(a.date);
    if (sortMode === "oldest") return new Date(a.date) - new Date(b.date);
    if (sortMode === "name") return a.url.localeCompare(b.url);
    return 0;
  });

  return (
    <div className="bookmark-container">
      <h1 className="bookmark-header">Bookmarked Pages</h1>

      {/* 링크 버튼 */}
      <div className="link-buttons">
        {linkButtons.map((btn) => (
          <div key={btn.id} style={{ position: "relative" }}>
            <button
              className={`link-btn ${btn.class}`}
              onClick={() => handleButtonClick(btn.id)}
            >
              {btn.name}
            </button>

            {showInput === btn.id && (
              <div className="bubble-input">
                <input
                  type="text"
                  placeholder="URL 입력"
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
        {sortedBookmarks.map((b) => (
          <div key={b.id} className="bookmark-card">
            {/* 🔹 상단에 고정된 Link 태그 */}
            <div className={`bookmark-tag link-${b.linkId}`}>
              {b.tag}
            </div>

            <div className="bookmark-title">
              <a 
                href={b.url} 
                target="_blank" 
                rel="noopener noreferrer"
                 onClick={(e) => e.stopPropagation()} //  클릭 전파 차단
                >
                {b.url}
              </a>
            </div>

            <div className="bookmark-desc">
              {b.desc ? b.desc : "생성된 룰 없음"}
            </div>

            <div className="bookmark-footer">
              <img
                src={trashIcon}
                alt="delete"
                className="trash-icon"
                onClick={() => handleDeleteClick(b.id)}
              />
              <span className="bookmark-date">{b.date}</span>
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
              <button className="cancel-btn" onClick={cancelDelete}>
                취소
              </button>
              <button className="delete-btn" onClick={confirmDelete}>
                삭제
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default BookmarkList;