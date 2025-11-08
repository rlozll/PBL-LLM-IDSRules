// src/components/Login.js
import React, { useState } from 'react';
import { login } from '../api'; // api.js에서 로그인 함수 가져오기
import { ReactComponent as UserIcon } from './icons/user.svg';


function Login({ onLoginSuccess }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError(''); // 이전 에러 메시지 초기화
    const success = await login(password); // 백엔드 /api/login 호출 (api.js)

    if (success) {
      onLoginSuccess(); // 로그인 성공 시 App.js에 알림
    } else {
      setError('비밀번호가 올바르지 않습니다.');
    }
  };

  return (
    <div className="login-container"> {/* CSS 클래스 추가 */}
      <form onSubmit={handleSubmit}>
        <UserIcon className="user-icon" width="60" height="60" />
        <input
          type="password"
          placeholder="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={(e) => setPassword(e.target.value)}
          required
        />
        {error && <p className="error-message">{error}</p>} {/* 에러 메시지 표시 */}
      </form>
    </div>
  );
}

export default Login;