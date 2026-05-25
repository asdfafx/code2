# Codebase Learning Journal

This journal tracks your understanding of the codebase across learning sessions.

## Focus & Goals

- **Primary goal**: Understand how each feature in this log suspicious behavior analysis system is implemented.
- **Interested in**: Request flow, route-to-service mapping, database models, log parsing, rule/ML/LLM analysis, alerts, export, realtime monitoring, and admin/auth features.
- **Background**: Not specified yet.
- **Learning style**: Start with a feature map, then trace concrete request flows through the code.

## Concept Mastery Map

### Confident

### Learning

- Flask application factory and blueprint registration.
- Route-to-service feature structure.
- Data chain: User -> LogImport -> LogEntry -> AnalysisResult, plus LLMModel for model configuration.
- Log import flow: upload/paste -> parser -> LogImport/LogEntry -> optional WebSocket broadcast.
- Analysis flow: rule pre-screening enriches LogEntry, then LLMService builds prompts, calls model APIs, parses JSON, and persists AnalysisResult.

### Need to Explore

- Authentication and role control.
- ML detector flow.
- Realtime stream and websocket monitoring.
- Alerts, timeline, geo, export, and admin workflows.

## Open Questions

- [ ] Which feature should be traced first in detail?
- [x] How does a raw uploaded log become a stored record and analysis result? - **Answer**: File/text input creates a LogImport, LogParser creates LogEntry rows, RuleFilter writes initial risk score/keywords, and LLMService can create AnalysisResult rows.

## Spaced Review Queue

- [ ] Flask blueprint feature split (review by: 2026-05-24) - 1st review

## Aha Moments

## Session Log

### 2026-05-23

- **Explored**: Initial repository structure.
- **Learned**: The project is a Flask app organized around route blueprints and service modules. The main feature path is log import, rule pre-screening, LLM/ML/stream analysis, then reports, statistics, alerts, geo, timeline, and admin management.
- **Struggled with**: Not yet assessed.
- **Next**: Trace one concrete workflow in detail, preferably "upload log -> pre-screen -> LLM analysis -> export".
