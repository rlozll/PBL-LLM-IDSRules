const API_BASE_URL = 'http://127.0.0.1:8000'; // FastAPI 서버 주소

// --- 로그인 관련 ---
export async function login(password) {
  try {
    // FastAPI OAuth2PasswordRequestForm expects form-url-encoded with fields username,password
    const form = new URLSearchParams();
    form.append('username', 'dashboard_user'); // app.py에서 sub으로 사용중
    form.append('password', password);

    const response = await fetch(`${API_BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });

    if (!response.ok) {
      return false;
    }

    const data = await response.json();

    // app.py 리턴: { "access_token": "...", "token_type": "bearer" }
    const token = data.access_token || data.token || data.accessToken;
    if (token) {
      // 통일: localStorage에 'token' 키로 저장
      localStorage.setItem('token', token);
      return true;
    }
    return false;
  } catch (error) {
    console.error('Login error:', error);
    return false;
  }
}

// 로그인 상태 체크 (localStorage 기준으로 통일)
export const checkLoginStatus = async () => {
  const token = localStorage.getItem('token');
  return !!token;
};

// --- 인증 필요한 API 호출 헬퍼 (localStorage 기준) ---
const fetchWithAuth = async (endpoint, options = {}) => {
  const token = localStorage.getItem('token'); // <-- 반드시 localStorage에서 읽음

  // 기본 헤더 (options.headers가 있으면 merge)
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  if (token) headers['Authorization'] = `Bearer ${token}`;

  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
    });

    // 401 받으면 토큰 제거하고 에러 처리 (로그인 UI로 유도는 호출자에서)
    if (response.status === 401) {
      localStorage.removeItem('token');
      // don't auto-reload here; let caller handle it (or you can reload if desired)
      throw new Error('Unauthorized');
    }

    return response;
  } catch (error) {
    console.error(`API call to ${endpoint} failed:`, error);
    throw error;
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

export const deployRule = async (rule_string) => {
  try {
    const response = await fetchWithAuth('/api/deploy-rule', {
      method: 'POST',
      body: JSON.stringify({ rule: rule_string }),
    });
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, data: data };
  } catch (error) {
    console.error('Deploy rule API call failed:', error);
    return { ok: false, status: 500, data: {detail: `네트워크 오류: ${error.message}`}};
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
    return await response.json(); 
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
      body: JSON.stringify({ url: url, site_name: siteName, link_id: linkId }),
    });
    return await response.json(); 
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
        return await response.json(); 
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
        return await response.json(); 
    } catch (error) {
        console.error('Get bookmark detail API call failed:', error);
        return null;
    }
};

// 삭제: 북마크 분석 결과 하나 삭제
export const deleteBookmarkResult = async (resultId) => {
  try {
    const response = await fetchWithAuth(`/api/bookmark-results/${resultId}`, {
      method: 'DELETE',
    });
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, data };
  } catch (error) {
    console.error('Delete bookmark result API call failed:', error);
    return { ok: false, status: 500, data: { detail: error.message } };
  }
};

// ----------------- History API -----------------

// 히스토리 목록 가져오기
export const getHistoryRecords = async () => {
  try {
    const response = await fetchWithAuth('/api/history');
    if (!response.ok) throw new Error('Failed to fetch history');
    return await response.json();
  } catch (error) {
    console.error('Get history API call failed:', error);
    return [];
  }
};

// 특정 히스토리 상세 가져오기
export const getHistoryDetail = async (id) => {
  try {
    const response = await fetchWithAuth(`/api/history/${id}`);
    if (!response.ok) throw new Error('Failed to fetch history detail');
    return await response.json();
  } catch (error) {
    console.error('Get history detail failed:', error);
    return null;
  }
};

// 새 히스토리 생성 (URL 입력 후 분석)
export const addHistoryRecord = async (url) => {
  try {
    const response = await fetchWithAuth('/api/history', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
    const data = await response.json();
    return { ok: response.ok, data };
  } catch (error) {
    console.error('Add history record failed:', error);
    return { ok: false, data: { detail: error.message } };
  }
};
