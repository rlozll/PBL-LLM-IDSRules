// src/api.js

const API_BASE_URL = 'http://127.0.0.1:8000'; // FastAPI 서버 주소

// --- 로그인 관련 ---
export const login = async (password) => {
  try {
    // 백엔드에 /api/login 엔드포인트가 필요합니다.
    // 이 엔드포인트는 password를 받아 .env의 DASHBOARD_PASSWORD와 비교 후
    // 성공 시 { "access_token": "your_jwt_token" } 형태의 응답을 반환해야 합니다.

    const formData = new FormData();
    formData.append('username', 'dashboard_user');
    formData.append('password', password);

    const response = await fetch(`${API_BASE_URL}/api/login`, {
        method: 'POST',
//      headers: { 'Content-Type': 'application/json' },
//      body: JSON.stringify({ password: password }),
	body: formData,
    });

    if (!response.ok) return false;
    const data = await response.json();
    if (data.access_token) {
      sessionStorage.setItem('authToken', data.access_token); // 세션 스토리지에 토큰 저장
      return true;
    }
    return false;
  } catch (error) {
    console.error('Login API call failed:', error);
    return false;
  }
};

export const checkLoginStatus = async () => {
    const token = sessionStorage.getItem('authToken');
    // 실제로는 백엔드에 토큰 유효성 검사 요청을 보내는 것이 더 안전합니다.
    // 여기서는 간단히 토큰 존재 여부만 확인합니다.
    return !!token;
};

// --- 인증 필요한 API 호출 헬퍼 ---
const fetchWithAuth = async (endpoint, options = {}) => {
    const token = sessionStorage.getItem('authToken');
    const headers = {
        ...options.headers,
        'Content-Type': 'application/json',
    };
    // JWT 토큰이 있으면 Authorization 헤더 추가
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, {
            ...options,
            headers: headers,
        });

        // 401 Unauthorized 에러 시 자동 로그아웃 처리
        if (response.status === 401) {
            sessionStorage.removeItem('authToken');
            window.location.reload(); // 페이지 새로고침하여 로그인 화면으로
            throw new Error('Unauthorized');
        }
        return response; // response 객체 자체를 반환
    } catch (error) {
         console.error(`API call to ${endpoint} failed:`, error);
         throw error; // 에러를 다시 던져서 호출한 곳에서 처리하도록 함
    }
};


// --- Rule 생성 API ---
export const generateRule = async (url) => {
  try {
    const response = await fetchWithAuth('/api/generate-rule', {
      method: 'POST',
      body: JSON.stringify({ url: url }),
    });
    // 상태 코드와 관계없이 일단 json() 호출 시도
    const data = await response.json();
    // 응답 객체와 파싱된 데이터를 함께 반환
    return { ok: response.ok, status: response.status, data: data };
  } catch (error) {
    console.error('Generate rule API call failed:', error);
    // 네트워크 오류 등 fetch 자체가 실패한 경우
    return { ok: false, status: 500, data: { detail: `네트워크 오류: ${error.message}` } };
  }
};

// --- 히스토리 API (백엔드 /api/history 필요) ---
export const getHistory = async () => {
  try {
    const response = await fetchWithAuth('/api/history');
    if (!response.ok) throw new Error('Failed to fetch history');
    return await response.json();
  } catch (error) {
    console.error('Get history API call failed:', error);
    return [];
  }
};

// --- CTI 리스트 API (백엔드 /api/new_cti_list 필요) ---
export const getNewCtiList = async () => {
    try {
      const response = await fetchWithAuth('/api/new_cti_list');
      if (!response.ok) throw new Error('Failed to fetch CTI list');
      return await response.json();
    } catch (error) {
      console.error('Get CTI list API call failed:', error);
      return [];
    }
};

// --- ▼▼▼ Bookmarked Pages용 API 함수 추가 ▼▼▼ ---

// 1. 현재 등록된 북마크 사이트 목록 가져오기
export const getBookmarkSites = async () => {
  try {
    const response = await fetchWithAuth('/api/bookmark-sites');
    if (!response.ok) throw new Error('Failed to fetch bookmark sites');
    return await response.json(); // 예: [{id: 1, url: "...", site_name: "..."}, ...]
  } catch (error) {
    console.error('Get bookmark sites API call failed:', error);
    return [];
  }
};

// 2. 새 북마크 사이트 등록하기
export const addBookmarkSite = async (url, siteName, linkId) => {
  try {
    const response = await fetchWithAuth('/api/bookmark-sites', {
      method: 'POST',
      body: JSON.stringify({ url: url, site_name: siteName, link_id: linkId }), // linkId 등 필요한 정보 전달
    });
    return await response.json(); // 예: { status: "success", data: {...} }
  } catch (error) {
    console.error('Add bookmark site API call failed:', error);
    return { status: "error", detail: error.message };
  }
};

// 3. 북마크 자동 분석 결과 (피드) 목록 가져오기
export const getBookmarkResults = async () => {
    try {
        const response = await fetchWithAuth('/api/bookmark-results');
        if (!response.ok) throw new Error('Failed to fetch bookmark results');
        return await response.json(); // 예: [{id: 1, post_url: "...", post_title: "...", ...}, ...]
    } catch (error) {
        console.error('Get bookmark results API call failed:', error);
        return [];
    }
};

// 4. 북마크 상세 결과 1개 가져오기 (Home 화면 재현용)
export const getBookmarkResultDetail = async (recordId) => {
    try {
        const response = await fetchWithAuth(`/api/bookmark-results/${recordId}`);
        if (!response.ok) throw new Error('Failed to fetch bookmark detail');
        return await response.json(); // RuleResponse 스키마와 동일한 형식
    } catch (error) {
        console.error('Get bookmark detail API call failed:', error);
        return null;
    }
};


// --- (추가) Rule 배포 API (백엔드 /api/deploy 필요) ---
// export const deployRule = async (ruleString) => { ... };
