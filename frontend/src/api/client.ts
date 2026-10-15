export interface ApiErrorResponse {
  detail?: string;
  message?: string;
}

export class ApiError extends Error {
  status: number;
  data?: ApiErrorResponse;

  constructor(status: number, message: string, data?: ApiErrorResponse) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

export function getAuthToken(): string | null {
  return localStorage.getItem('token');
}

export function setAuthToken(token: string): void {
  localStorage.setItem('token', token);
}

export function clearAuthToken(): void {
  localStorage.removeItem('token');
}

export async function apiRequest<T = any>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getAuthToken();
  const headers = new Headers(options.headers || {});

  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  if (options.body && !(options.body instanceof FormData) && !(options.body instanceof URLSearchParams)) {
    if (!headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
  }

  const response = await fetch(endpoint, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    clearAuthToken();
  }

  if (!response.ok) {
    let errorDetail = `Request failed with status ${response.status}`;
    let errData: ApiErrorResponse | undefined;
    try {
      errData = await response.json();
      if (errData?.detail) {
        errorDetail = errData.detail;
      } else if (errData?.message) {
        errorDetail = errData.message;
      }
    } catch {
      // not JSON
    }
    throw new ApiError(response.status, errorDetail, errData);
  }

  // Handle empty or blob responses
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return response.json() as Promise<T>;
  }
  return response.text() as unknown as Promise<T>;
}

export const api = {
  get: <T = any>(url: string, options?: RequestInit) =>
    apiRequest<T>(url, { ...options, method: 'GET' }),
  post: <T = any>(url: string, body?: any, options?: RequestInit) =>
    apiRequest<T>(url, {
      ...options,
      method: 'POST',
      body: body instanceof FormData || body instanceof URLSearchParams ? body : JSON.stringify(body),
    }),
  patch: <T = any>(url: string, body?: any, options?: RequestInit) =>
    apiRequest<T>(url, {
      ...options,
      method: 'PATCH',
      body: JSON.stringify(body),
    }),
  delete: <T = any>(url: string, options?: RequestInit) =>
    apiRequest<T>(url, { ...options, method: 'DELETE' }),
};
