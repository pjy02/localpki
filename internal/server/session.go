package server

import (
    crand "crypto/rand"
    "encoding/base64"
    "sync"
    "time"
)

type session struct {
    Username string
    Expires  time.Time
    Values   map[string][]byte
}

type SessionManager struct {
    mu       sync.Mutex
    sessions map[string]*session
}

func NewSessionManager() *SessionManager {
    return &SessionManager{sessions: make(map[string]*session)}
}

func (m *SessionManager) Create(username string, ttl time.Duration) (string, *session) {
    token := randomToken(32)
    sess := &session{
        Username: username,
        Expires:  time.Now().Add(ttl),
        Values:   make(map[string][]byte),
    }
    m.mu.Lock()
    m.sessions[token] = sess
    m.mu.Unlock()
    return token, sess
}

func (m *SessionManager) Get(token string) (*session, bool) {
    m.mu.Lock()
    defer m.mu.Unlock()
    sess, ok := m.sessions[token]
    if !ok {
        return nil, false
    }
    if time.Now().After(sess.Expires) {
        delete(m.sessions, token)
        return nil, false
    }
    return sess, true
}

func (m *SessionManager) Touch(token string, ttl time.Duration) {
    m.mu.Lock()
    defer m.mu.Unlock()
    if sess, ok := m.sessions[token]; ok {
        sess.Expires = time.Now().Add(ttl)
    }
}

func (m *SessionManager) Destroy(token string) {
    m.mu.Lock()
    delete(m.sessions, token)
    m.mu.Unlock()
}

func (m *SessionManager) Set(token, key string, value []byte) {
    m.mu.Lock()
    defer m.mu.Unlock()
    if sess, ok := m.sessions[token]; ok {
        sess.Values[key] = value
    }
}

func (m *SessionManager) Pop(token, key string) ([]byte, bool) {
    m.mu.Lock()
    defer m.mu.Unlock()
    sess, ok := m.sessions[token]
    if !ok {
        return nil, false
    }
    value, ok := sess.Values[key]
    if ok {
        delete(sess.Values, key)
    }
    return value, ok
}

func randomToken(n int) string {
    buf := make([]byte, n)
    if _, err := crand.Read(buf); err != nil {
        panic(err)
    }
    return base64.RawURLEncoding.EncodeToString(buf)
}
