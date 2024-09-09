# Lern-IDApython
Học IDAPython với ckagngoc 💀

## I. Tài liệu học tập được đề xuất cho IDA python
- ida权威指南第二版》
- [https://wooyun.js.org/drops/IDAPython%20%E8%AE%A9%E4%BD%A0%E7%9A%84%E7%94%9F%E6%B4%BB%E6%9B%B4%E6%BB%8B%E6%B6%A6%20part1%20and%20part2.html](https://wooyun.js.org/drops/IDAPython 让你的生活更滋润 part1 and part2.html)
- https://cartermgj.github.io/2017/10/10/ida-python/
- https://www.hex-rays.com/products/ida/support/idapython_docs/
-《idapython book》有中文版本的翻译
- https://bbs.pediy.com/thread-225091.htm python模拟执行x86，基于idapython
- 《The Beginner’s Guide to IDAPython version 6.0》

## II. Giới thiệu

Lõi IDAPython có 3 module python sau:
1. **idc** Chịu trách nhiệm cung cấp tất cả chức năng trong IDC.
2. **idautils** cung cấp các hàm tiện ích, nhiều hàm tạo ra danh sách
3. **idaapi** cho phép người udngf truy cập nhiều dữ liệu cơ bản dưới dạng các lớp

Hầu hết các script viết ra đều **import** các module này ngay từ đầu

### 1. Các thao tác cơ bản

Nhận địa chỉ hiện tại
```
idc.here()
idc.get_screen_ea()
```

Lấy địa chỉ min và max của không gian địa chỉ
```
idc.get_inf_attr(idc.INF_MIN_EA)
idc.get_inf_attr(idc.INF_MAX_EA)
```

Ví dụ trong IDA có câu lệnh sau
```
.text:00012529 mov esi, [esp+4+arg_0]
```
Ta có thể lấy các thông tin như sau:
```
Python> idc.get_segm_name(here())
'.text'

Python> idc.GetDisasm(here())
'call    sub_405060'

Python>idc.print_insn_mnem(here())
'call'

Python>idc.print_operand(here(),0)
'sub_405060'

Python>idc.print_operand(here(),1)
''
```

### 2. Thao tác với segment

Lặp qua các segments
```
import idc
import idaapi
import idautils

for seg in idautils.Segments():
    print(idc.get_segm_name(seg), idc.gẻ_segm_start(seg), idc.get_segm_end(seg))
```

### 3. Thao tác với hàm

Lặp qua tất cả các hàm
```
for func in idautils.Functions():
    print(func, idc.get_func_name(func))
```

- **Functions()** sẽ trả về địa chỉ đầu tiên của một hàm đã biết. Hàm này cũng được sử dụng để tìm địa chỉ các hàm trong danh sách được hcir định.
- **get_func_name(ea)** được sử dụng để lấy tên hàm, tham số ea có thể là bất cứ địa chỉ nào trong hàm
- **idaapi.get_func_qty()** lấy số lượng hàm đã nhận dạng được
- **idaapi.get_func(1)** lấy đối tượng func_t của hàm đầu tiên

Lấy thông tin giới hạn của một hàm
```
Python>idaapi.get_func(here())
<ida_funcs.func_t; proxy of <Swig Object of type 'func_t *' at 0x000001711FC33C00> >
Python>idaapi.get_func(here()).start_ea
0x40573c
Python>idaapi.get_func(here()).end_ea
0x405918
```