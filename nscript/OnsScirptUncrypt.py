def xor_file_hex(input_filename, output_filename, xor_value, chunk_size=16):
    try:
        with open(input_filename, 'rb') as f_in, open(output_filename, 'w') as f_out:
            while True:
                # 每次读取 chunk_size 字节
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break

                #XOR 0x86
                xor_chunk = bytes([byte ^ xor_value for byte in chunk])
                #print(xor_chunk)
                # 转换为十六进制字符串并写入
                f_out.write(xor_chunk.hex())

        print(f"处理完成，结果已保存: {output_filename}")

    except FileNotFoundError:
        print(f"文件 {input_filename} 未找到")
    except Exception as e:
        print(f"发生错误: {str(e)}")

def rewriter():
    with open("nscript.txt", "r") as file:
        hex_str = file.read().strip()

    hex_str = "".join(hex_str.split())

    try:
        bytes_data = bytes.fromhex(hex_str)
    except ValueError as e:
        print(f"十六进制字符串无效 - {e}")
        exit(1)

    text = bytes_data.decode("gbk")

    with open("nscript.txt", "w", encoding="gbk") as file:

        file.write(text)

    print("文字已成功写入文件喵！")

    #print("转换后的文字：")
    #print(text)



input_file = "nscript.dat"
output_file = "nscript.txt"
xor_value = 0x84
chunk_size = 8  # 16字节块读取

xor_file_hex(input_file, output_file, xor_value, chunk_size)
rewriter()