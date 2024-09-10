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

Bên cạnh đó có thể sử dụng hàm **idc.get_next_func(ea)** và **idc.get_prev_func(ea)** để lấy func_t của hàm trước và sau địa chỉ ea. Giá trị của ea cần phải nằm trong giá trị của 1 hàm nhất định đang được phân tích. Mã không được đánh dấu là hàm sẽ có chữ đỏ, lúc này ta cần sửa thủ công.
Có thể sử dụng các api sau để lấy start và end của hàm 
```
# Lấy start ea của hàm
ea = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)
# Lấy end của hàm
ea = idc.get_func_attr(idc.here(), idc.FUNCATTR_END)

# Các tham số của hàm get_func_attr() có các giá trị như dưới đây
FUNCATTR_START = 0          # địa chỉ bắt đầu hàm
FUNCATTR_END = 4            # địa chỉ kết thúc hàm
FUNCATTR_FLAGS = 8          # giá trị cờ của hàm
FUNCATTR_FRAME = 10         # id khung stack của hàm
FUNCATTR_FRSIZE = 14        # kích thước biến cục bộ
FUNCATTR_FRREGS = 18        # kích thước vùng thanh ghi đã lưu
FUNCATTR_ARGSIZE = 20       # số lượng bytes được xóa khỏi stack
FUNCATTR_FPD = 24           # con trỏ khung delta
FUNCATTR_COLOR = 28         # mã màu hàm
FUNCATTR_OWNER = 10         # chunk owner
FUNCATTR_REFQTY = 14        # số lượng chunk cha

# Lấy địa chỉ hàm nếu có tên của nó
idc.get_name_ea_simple("<tên hàm>")
```

Để duyệt tất cả câu lệnh của 1 hàm sử dụng code sau
```
import idc
import idaapi
import idautils

start = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)
end = idc.get_func_attr(idc.here(), idc.FUNCATTR_END)

curr_addr = start

while curr_addr <= end:
    print(hex(curr_addr), idc.GetDisasm(curr_addr))
    curr_addr = idc.next_head(curr_addr, end)
```

Hàm **idc.next_head(curr_addr, end)** sẽ trả về địa chỉ đầu tiên của lệnh tiếp theo giữa curr_addr và end hoặc nếu không có lệnh nào sẽ trả về idc.BADADDR, ngược với nó là hàm **idc.prev_head(curr_addr, end)**. Cách duyệt câu lệnh này chỉ áp dụng đối với các hàm chỉ có các câu lệnh nằm giữa start và end nên nếu trong hàm có một lệnh **jmp** nhảy sang vị trí khác bên ngoài sau đó quay lại địa chỉ giữa start và end thì khi duyệt sẽ bị sót câu lệnh.
Để duyệt đầy dủ các thành phần của hàm ta có thể sử dụng idautils.FuncItems(ea) để lặp các hướng dẫn trong hàm cụ thể ở phần dưới.

Để lấy cờ của hàm có thể sử dụng đoạn mã sau

```
import idc
import idaapi
import idautils

for func in idautils.Functions():
    flags = idc.get_func_attr(func. idc.FUNCATTR_FLAGS)
    if flags & FUNC_NORET:
        print(hex(func), "FUNC_NORET")
    if flags & FUNC_FAR:
        print(hex(func), "FUNC_FAR")
    if flags & FUNC_USERFAR:
        print(hex(func), "FUNC_USERFAR")
    if flags & FUNC_LIB:
        print(hex(func), "FUNC_LIB")
    if flags & FUNC_FRAME:
        print(hex(func), "FUNC_FRAME")
    if flags & FUNC_BOTTOMBP:
        print(hex(func), "FUNC_BOTTOMBP")
    if flags & FUNC_HIDDEN:
        print(hex(func), "FUNC_HIDDEN")
    if flags & FUNC_THUNK:
        print(hex(func), "FUNC_THUNK")
```

Ý nghĩa các cờ của hàm
```
FUNC_NORET: Cờ này cho biết hàm có giá trị trả về hay không. Giá trị của nó là 1. Sau đây là hàm không có giá trị trả về. 
Lưu ý rằng phần cuối của hàm không có giá trị trả về không phải là lệnh ret hoặc left.

FUNC_FAR: Cờ này rất hiếm khi xuất hiện và cho biết chương trình có sử dụng bộ nhớ được phân đoạn hay không .

FUNC_USERFAR: Cờ này cũng rất hiếm và hiếm khi được ghi lại. HexRays mô tả nó là "người dùng đã chỉ định độ sâu 
của hàm" và giá trị của nó là 32.

FUNC_LIB: Mã này thể hiện mã được sử dụng để tìm các hàm thư viện. Việc xác định mã hàm thư viện là rất cần thiết vì chúng ta 
thường bỏ qua nó trong quá trình phân tích và giá trị của nó là 4 . Ví dụ sau đây cho thấy cách sử dụng cờ này.

for func in idautils.Functions():
    flags = idc.get_func_attr(func, FUNCATTR_FLAGS)

    if flags & FUNC_LIB:
        print(hex(func), "FUNC_LIB",get_func_name(func))

FUNC_FRAME: Cờ này cho biết hàm có sử dụng thanh ghi ebp (con trỏ khung) hay không. Các hàm sử dụng thanh ghi ebp thường có các cài đặt cú pháp 
sau để lưu khung ngăn xếp.

.text:00404C90                 push    ebp
.text:00404C91                 mov     ebp, esp
.text:00404C96                 sub     esp, 65Ch

FUNC_BOTTOMBP: Giống như FUNC_FRAME, cờ này được sử dụng để theo dõi con trỏ khung (ebp). Chức năng của nó là xác định xem con trỏ khung trong hàm có bằng con trỏ ngăn xếp (đặc biệt) 
hay không .

FUNC_HIDDEN: Các hàm có cờ FUNC_HIDDEN có nghĩa là chúng bị ẩn và hàm cần được mở rộng để xem được. 
Nếu chúng ta chuyển đến một địa chỉ được đánh dấu ẨN, địa chỉ đó sẽ tự động mở rộng.

FUNC_THUNK: Cho biết hàm này có phải là hàm thunk hay không. Hàm thunk đại diện cho một hàm nhảy đơn giản.

.text:1A710606 Process32Next proc near
.text:1A710606 jmp ds:__imp_Process32Next
.text:1A710606 Process32Next endp

Lưu ý rằng một hàm có thể có nhiều tổ hợp cờ.
```

### 4. Thao tác với câu lệnh

Nếu có địa chỉ của một hàm có thể duyệt tất cả câu lệnh trong hàm bằng cách sử dụng idautils.FuncItems(ea) như sau

```
import idc
import idautils
import idaapi

items = idautils.FuncItems(idc.here())

for item in items:
    print(hex(item), idc.GetDisasm(item))
```
#### Ví dụ nhỏ
Tìm tất cả các lệnh gọi động <lệnh gọi có sử dụng operand là thanh ghi> hoặc lệnh nhảy với toán hạng và tô màu cho lệnh đó để dễ tìm kiếm

```
import idc
import idautils
import idaapi

for func in idc.Functions():
    flags = idc.get_func_attr(func, idc.FUNCATTR_FLAGS)
    if flags & FUNC_LIB or flags & FUNC_THUNK:
        continue
    dism_addr = idautils.FuncItems(func)
    for line in dism_addr:
        m = idc.print_insn_mnem(line)
        if m == "call" or m == "jmp":
            op = idc.get_operand_type(line, 0)
            if op == o_reg:
                print(hex(line), idc.GetDisasm(line))
```

idc.get_operand_type(ea, n) lấy loại toán hạng thứ n, các loại toán hạng sẽ được đề cập ở phần dưới.
##### Note: Nếu muốn lấy địa chỉ tiếp theo mà không phải câu lệnh tiếp theo từ ea thì dùng lệnh **idc.next_addr** và **idc.prev_addr**

### 5. Thao tác với toán hạng

Để lấy loại toán hạng ta sử dụng hàm idc.get_operand_type(ea,n) trong đó ea là địa chỉ đầu lệnh và n là chỉ mục của toán hạng. Có các loại toán hạng như sau:

```
o_void: Nếu lệnh không có toán hạng nào, nó sẽ trả về 0 . 
----------------------------------------------------
o_reg: Nếu toán hạng là một thanh ghi, hãy trả về loại này, giá trị của nó là 1
----------------------------------------------------
o_mem: Nếu toán hạng là địa chỉ bộ nhớ trực tiếp thì trả về loại này, giá trị của nó là 2 , loại này rất hữu ích cho việc tìm kiếm 
các trích dẫn DỮ LIỆU rất hữu ích.

Python>print hex(ea), idc.GetDisasm(ea) 
0xa05d86 cmp ds:dword_A152B8, 0
Python>print idc.GetOpType(ea, 0) 
2
----------------------------------------------------
o_phrase: Nếu toán hạng là một thao tác đánh địa chỉ sử dụng thanh ghi địa chỉ cơ sở và thanh ghi chỉ mục thì loại này được trả về và giá trị là 3

Python>print hex(ea), idc.GetDisasm(ea) 
0x1000b8c2 mov [edi+ecx], eax 
Python>print idc.GetOpType(ea, 0) 
3
----------------------------------------------------
o_displ: Nếu toán hạng là một thao tác đánh địa chỉ sử dụng các thanh ghi và phép dịch chuyển, thì loại này được trả về và giá trị là 4. Độ dịch chuyển đề cập đến 0x18 như trong đoạn mã sau . Điều này rất phổ biến khi lấy dữ liệu nhất định trong một cấu trúc.

Python>print hex(ea), idc.GetDisasm(ea) 
0xa05dc1 mov eax, [edi+ 18h] 
Python>print idc.GetOpType(ea, 1) 
4
----------------------------------------------------
o_imm: Nếu toán hạng là giá trị xác định thì kiểu trả về là 5

Python>print hex(ea), idc.GetDisasm(ea) 
0xa05da1 add esp, 0 Ch 
Python>print idc.get_operand_type(ea, 1) 
5
--------------------------------------------------- 
o_far: Kiểu trả về này là nghịch đảo của x86 và x86_64 Không phổ biến. Nó được sử dụng để xác định toán hạng truy cập trực tiếp vào địa chỉ từ xa. Giá trị là 6
----------------------------------------------------
o_near: Kiểu trả về này không phổ biến trong kỹ thuật đảo ngược x86 và x86_64. Nó được sử dụng để xác định toán hạng truy cập trực tiếp vào địa chỉ cục bộ, giá trị là 7
```