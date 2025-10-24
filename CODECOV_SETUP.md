# Codecov 설정 가이드

GitHub에서 커버리지를 바로 보려면 Codecov를 설정하세요.

## 1. Codecov 가입 및 연동

1. [Codecov](https://about.codecov.io/) 접속
2. GitHub 계정으로 로그인
3. `hapiService/auth-service` 저장소 선택

## 2. Codecov 토큰 발급

1. Codecov 대시보드에서 저장소 선택
2. Settings > Repository Upload Token 복사

## 3. GitHub Secrets 설정

1. GitHub 저장소 > Settings > Secrets and variables > Actions
2. `New repository secret` 클릭
3. Name: `CODECOV_TOKEN`
4. Value: 위에서 복사한 토큰 붙여넣기
5. Add secret 클릭

## 4. 완료!

이제 CI가 실행될 때마다:
- ✅ 커버리지가 자동으로 Codecov에 업로드
- ✅ README의 배지에 커버리지 표시
- ✅ PR에 커버리지 변화 코멘트 추가
- ✅ Codecov 대시보드에서 상세 리포트 확인

## 대체 방법: Coveralls

Codecov 대신 [Coveralls](https://coveralls.io/)를 사용할 수도 있습니다:

1. Coveralls 가입
2. GitHub Actions에서 `coverallsapp/github-action@v2` 사용
3. `COVERALLS_REPO_TOKEN` secret 추가

## 로컬에서 커버리지 확인

```bash
./gradlew test jacocoTestReport
open build/reports/jacoco/test/html/index.html
```
