#!/usr/bin/env bash
# =============================================================================
#  make_release.sh — собрать версионный zip-архив релиза
#
#  По умолчанию только собирает архив в dist/ — ничего не публикует.
#  Действия наружу (тег, push, GitHub Release) включаются флагами явно.
#
#  Использование:
#    ./scripts/make_release.sh                 # собрать dist/<name>-v1.0.0.zip
#    ./scripts/make_release.sh --tag           # + создать локальный тег
#    ./scripts/make_release.sh --tag --push    # + отправить тег в origin
#    ./scripts/make_release.sh --tag --push --github   # + GitHub Release с файлом
#
#  После push тега GitHub сам отдаёт архив по адресу:
#    https://github.com/<owner>/<repo>/archive/refs/tags/<tag>.zip
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$ROOT"

DO_TAG=false; DO_PUSH=false; DO_GITHUB=false
for arg in "$@"; do
    case "$arg" in
        --tag)    DO_TAG=true ;;
        --push)   DO_TAG=true; DO_PUSH=true ;;
        --github) DO_TAG=true; DO_PUSH=true; DO_GITHUB=true ;;
        -h|--help) sed -n '3,17p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) log_error "Неизвестный параметр: $arg"; exit 1 ;;
    esac
done

[[ -f VERSION ]] || { log_error "Файл VERSION не найден"; exit 1; }
VERSION="$(tr -d ' \t\r\n' < VERSION)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    log_error "VERSION должен быть вида X.Y.Z, а не '${VERSION}'"; exit 1; }

NAME="mysql-ai-monitoring"
TAG="v${VERSION}"
OUT="dist/${NAME}-${TAG}.zip"

echo ""
echo -e "${BOLD}${BLUE}Сборка релиза ${TAG}${NC}"
echo ""

# ── Проверки перед сборкой ───────────────────────────────────────────────────
if [[ -n "$(git status --porcelain)" ]]; then
    log_error "Рабочее дерево грязное — закоммитьте или спрячьте изменения:"
    git status --short
    exit 1
fi

if git rev-parse "$TAG" >/dev/null 2>&1; then
    log_warn "Тег ${TAG} уже существует"
    DO_TAG=false
    if [[ "$DO_PUSH" == "true" ]]; then
        log_error "Поднимите версию в VERSION или удалите тег вручную"
        exit 1
    fi
fi

# ── Сборка ───────────────────────────────────────────────────────────────────
# git archive берёт ТОЛЬКО отслеживаемые файлы: config.env, базы и прочее
# из .gitignore физически не могут попасть в архив.
mkdir -p dist
git archive --format=zip \
            --prefix="${NAME}-${VERSION}/" \
            -o "$OUT" HEAD

SIZE=$(du -h "$OUT" | cut -f1)
FILES=$(git ls-files | wc -l)
log_info "Собран ${OUT} (${SIZE}, файлов: ${FILES})"

# Страховка: секретов в архиве быть не должно
if unzip -l "$OUT" 2>/dev/null | grep -qE "config\.env|\.db$"; then
    log_error "В архив попали config.env или база — проверьте .gitignore"
    exit 1
fi
log_info "Секретов в архиве нет ✓"

# ── Тег ──────────────────────────────────────────────────────────────────────
if [[ "$DO_TAG" == "true" ]]; then
    git tag -a "$TAG" -m "Release ${TAG}"
    log_info "Создан тег ${TAG}"
fi

if [[ "$DO_PUSH" == "true" ]]; then
    git push origin "$TAG"
    log_info "Тег отправлен в origin"

    REMOTE="$(git remote get-url origin)"
    SLUG="$(printf '%s' "$REMOTE" | sed -E 's#(git@|https://)github.com[:/]##; s#\.git$##')"
    echo ""
    echo -e "${BOLD}Скачать архив этой версии:${NC}"
    echo "  https://github.com/${SLUG}/archive/refs/tags/${TAG}.zip"
fi

if [[ "$DO_GITHUB" == "true" ]]; then
    if command -v gh >/dev/null 2>&1; then
        gh release create "$TAG" "$OUT" \
            --title "$TAG" \
            --notes "Версия ${VERSION}. Архив собран из отслеживаемых файлов, секретов не содержит."
        log_info "GitHub Release ${TAG} создан, архив приложен"
    else
        log_warn "gh не установлен — Release не создан."
        log_warn "Приложите ${OUT} вручную: Releases → Draft a new release → ${TAG}"
    fi
fi

echo ""
echo -e "${BOLD}Дальше:${NC}"
[[ "$DO_TAG"  == "false" ]] && echo "  Создать тег:      ./scripts/make_release.sh --tag"
[[ "$DO_PUSH" == "false" ]] && echo "  Опубликовать:     ./scripts/make_release.sh --tag --push"
echo "  Поднять версию:   отредактируйте VERSION"
echo ""
