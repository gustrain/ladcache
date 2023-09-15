K=$((1024))
M=$((1024 * K))
G=$((1024 * M))

# Test configuration.
SIZE_PER_CATEGORY=$((1 * G))
CATEGORIES=(
    $((64  * $K)),  # 64KB
    $((256 * $K)),  # 256KB
    $((1   * $M)),  # 1MB
    $((4   * $M)),  # 4MB
    $((16  * $M)),  # 16MB
    $((64  * $M)),  # 32MB
    $((256 * $M)),  # 256MB
    $((1   * $G))   # 1GB
)

for CATEGORY in ${CATEGORIES[@]}; do
    echo "creating $((SIZE_PER_CATEGORY / CATEGORY)) $((CATEGORY / K))KB files"

    N_FILES=$((CATEGORY / K))
    DIR_NAME=$($N_FILES)KB
    mkdir $DIR_NAME
    for N in $(seq 1 $((SIZE_PER_CATEGORY/CATEGORY))); do
        fallocate -l $CATEGORY $DIR_NAME/$(printf %08d "$N")

        # Progress reports
        if [ $(($N % $((N_FILES / 16)))) -eq 0 ]; then
            echo "$N/$N_FILES"
        fi
    done
done