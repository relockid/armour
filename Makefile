include .env

$(eval build:;@:)

build:
	@echo "Building source..."
	python3 -m build
check:
	@echo "Check for errors pypi..."
	python3 -m twine check dist/*
test:
	@echo "Upload for testpypi..."
	python3 -m twine upload --repository testpypi dist/*
dry:
	python3 -m pip install --index-url https://test.pypi.org/simple/ --no-deps relock
upload:
	@echo "Release..."
	python3 -m twine upload dist/*
install:
	python3 -m pip install relock
commit:
	git commit -m "Release $(VERSION)"
	git push
pull:
	git pull
release:
ifeq ($(VERSION_SET),1)
	export VERSION=$(VERSION) && export APP_NAME=$(APP_NAME) && poetry run python setup.py py2app
	poetry version $(VERSION)
	git add pyproject.toml
	git commit -m "Release $(VERSION)"
	git push 
	cd dist && zip -r "$(APP_NAME).app.zip" "$(APP_NAME).app"
	gh release create $(VERSION) 'dist/$(APP_NAME).app.zip#$(APP_NAME).app.zip'
else
	$(error VERSION not defined - use like this: make release VERSION=...)
endif