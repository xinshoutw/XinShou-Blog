#!/usr/bin/env python3
# 將 Hackmd 中的筆記內容轉為 Gokarna 相容的顯示樣式
# Usage: ./Hackmd2blog.py ./target.md ./output.md
# Author: XinShou

import sys
import re


class Hackmd2blog:
    file_path: str
    content: str = None

    def __init__(self, file_path):
        self.file_path = file_path
        self.read_file()
        self.remove_hackmd_only_sections()
        self.remove_placeholder()
        self.convert_flag_info_spoiler()
        self.convert_spoiler()
        self.convert_code_block()
        self.convert_image_size_format()
        self.content = self.content.strip()

    # def parseTitle(self):
    #     extracted_text = re.search(r'^---(.*?)---', self.content, re.DOTALL)
    #     if not extracted_text:
    #         raise RuntimeError
    #
    #     extracted_text = extracted_text.group(1).strip()
    #     return extracted_text
    def read_file(self):
        with open(self.file_path, 'r') as f:
            self.content = f.read().strip()

    def remove_hackmd_only_sections(self):
        """
        Removes sections marked explicitly for Hackmd Only from the provided text.
        """
        self.content = re.sub(r'<!-- Hackmd Only -->.*?<!-- /Hackmd Only -->', '', self.content, flags=re.DOTALL)

    def convert_spoiler(self):
        """
        Converts Hackmd spoiler syntax to Hugo spoiler shortcode syntax.
        """
        converted_text = re.sub(r':::spoiler (.*)\n', r'{{< spoiler "\1" >}}\n', self.content)
        converted_text = re.sub(r':::\n', r'{{< /spoiler >}}\n', converted_text)
        self.content = converted_text

    def convert_flag_info_spoiler(self):
        """
        Converts Hackmd info block to Markdown blockquote.
        """
        self.content = re.sub(r':::info\n(.*)\n:::', r'> \1', self.content)

    def convert_code_block(self):
        """
        Converts standard Markdown code blocks to code blocks with inline line numbers.
        """
        self.content = re.sub(r'```([a-z]+)=', r'```\1 {linenos=inline}', self.content)

    def remove_placeholder(self):
        self.content = self.content.replace('<br />', '')

    def convert_image_size_format(self):
        """
        Converts Markdown image links from size format '=500x' to ' "500px"'.
        """
        self.content = re.sub(r'\(https://hackmd.io/_uploads/([^ ]+) =(\d+)x\)',
                              r'(https://hackmd.io/_uploads/\1 "\2px")', self.content)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: ./hackmd2blog target.md output.md")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    h2b = Hackmd2blog(input_file)
    with open(output_file, 'w') as f:
        f.write(h2b.content)
