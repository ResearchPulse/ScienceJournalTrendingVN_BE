@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "API_URL=http://localhost:5000/api/v1/auth/sso/bootstrap"
set "FRONTEND_ORIGIN=http://localhost:5173"
set "PAUSE_AT_END=1"

if not "%~1"=="" set "API_URL=%~1"
if not "%~2"=="" set "FRONTEND_ORIGIN=%~2"
if /I "%~3"=="--no-pause" set "PAUSE_AT_END=0"

where curl.exe >nul 2>&1
if errorlevel 1 (
  echo [ERROR] curl.exe was not found.
  set "FINAL_EXIT=1"
  goto :finish
)

echo Parent SSO local test
echo API: %API_URL%
echo Origin: %FRONTEND_ORIGIN%
echo.
echo Log in to the parent application, then copy its access_token from DevTools.
set /p "PARENT_TOKEN=Paste parent access_token: "

if not defined PARENT_TOKEN (
  echo [ERROR] access_token is required.
  set "FINAL_EXIT=2"
  goto :finish
)

echo.
echo Exchanging the parent token for a local child session...
echo.

curl.exe --silent --show-error --fail-with-body --include ^
  --connect-timeout 5 --max-time 20 ^
  --request POST "%API_URL%" ^
  --header "Authorization: Bearer %PARENT_TOKEN%" ^
  --header "Origin: %FRONTEND_ORIGIN%" ^
  --header "Content-Type: application/json" ^
  --data "{}" ^
  --write-out "\n[HTTP status] %%{http_code}\n"

set "CURL_EXIT=%ERRORLEVEL%"
set "PARENT_TOKEN="

echo.
if not "%CURL_EXIT%"=="0" (
  echo [FAILED] Request failed. Make sure the backend is running and the parent token is valid.
  set "FINAL_EXIT=%CURL_EXIT%"
  goto :finish
)

echo [OK] Bootstrap completed. Expected HTTP status: 200 and a child Set-Cookie header.
echo [NOTE] This validates the backend only. curl and Edge use different cookie jars.
echo [NOTE] To authenticate the open local UI, the browser itself must send the bootstrap request.
set "FINAL_EXIT=0"

:finish
set "PARENT_TOKEN="
echo.
if "%PAUSE_AT_END%"=="1" (
  echo Press any key to close this window...
  pause >nul
)
exit /b %FINAL_EXIT%
