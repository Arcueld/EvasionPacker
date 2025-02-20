def _HashStringRotr32SubA(value, count):
    # 计算掩码 (CHAR_BIT * sizeof(Value) - 1)
    mask = (8 * 4 - 1)  # 32-bit (DWORD) = 4 bytes = 32 bits
    count &= mask
    
    # 右移和左移操作
    return ((value >> count) | (value << ((-count) & mask))) & 0xFFFFFFFF  # 保证32位返回

def _HashStringRotr32A(string):
    # 初始化哈希值
    value = 0
    
    # 设置一个种子（可以根据需要调整，原文中没有定义 SEED）
    SEED = 0xD8  # 假设 SEED = 5（可以根据实际情况调整）

    # 遍历字符串，逐个字符参与哈希
    for char in string:
        value = ord(char) + _HashStringRotr32SubA(value, SEED)

    return value

# 测试函数
hash_value = _HashStringRotr32A("Sleep")
print(f"Hash Value: {hex(hash_value)}")
