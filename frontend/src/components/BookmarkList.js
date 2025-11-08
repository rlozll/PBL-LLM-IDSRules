import React, { useState } from "react";
import "./BookmarkList.css";
import trashIcon from "./icons/Trash1.svg";


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
  const [deleteTarget, setDeleteTarget] = useState(null); // 🔹 삭제 확인용

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
      tag: `Link ${id}`,
      linkId: id,
      url: inputValue,
      desc: "",
      date: getCurrentDateTime(),
    };

    setBookmarks((prev) => [newCard, ...prev]);
    setShowInput(null);
  };

  // 🔹 삭제 확인 팝업 띄우기
  const handleDeleteClick = (id) => {
    setDeleteTarget(id);
  };

  // 🔹 삭제 확정
  const confirmDelete = () => {
    setBookmarks((prev) => prev.filter((b) => b.id !== deleteTarget));
    setDeleteTarget(null);
  };

  // 🔹 삭제 취소
  const cancelDelete = () => {
    setDeleteTarget(null);
  };

  const sortedBookmarks = [...bookmarks].sort((a, b) => {
    if (sortMode === "latest") return new Date(b.date) - new Date(a.date);
    if (sortMode === "oldest") return new Date(a.date) - new Date(b.date);
    if (sortMode === "name") return a.url.localeCompare(b.url);
    return 0;
  });

  return (
    <div className="bookmark-container">
      <h1 className="bookmark-header">Bookmarked Pages</h1>

      {/* 버튼 */}
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
                  placeholder="URL 입력..."
                  value={inputValue}
                  onChange={(e) => setInputValue(e.target.value)}
                />
                <button onClick={() => handleAddBookmark(btn.id)}>등록</button>
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
            <span className={`bookmark-tag link-${b.linkId}`}>{b.tag}</span>

            <div className="bookmark-title">
              <a href={b.url} target="_blank" rel="noopener noreferrer">
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

      {/* 🔹 삭제 확인 팝업 */}
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