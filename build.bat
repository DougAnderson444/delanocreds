cargo doc --no-deps
rmdir /s ./docs
robocopy target/doc docs /s
echo|set /p="<meta http-equiv="refresh" content="0; url=delanocreds/index.html">" > docs/index.html