# Lern-IDApython
Học IDAPython với ckagngoc 💀

## Mục lục
[I. Tài liệu đề xuất](#i-tài-liệu-học-tập-được-đề-xuất-cho-ida-python)
-

[II. Giới thiệu các mục cơ bản](#ii-giới-thiệu)
-

[1-các-thao-tác-cơ-bản](#1-các-thao-tác-cơ-bản)

[2-thao-tác-với-segment](#2-thao-tác-với-segment)

[3-thao-tác-với-hàm](#3-thao-tác-với-hàm)

[4-thao-tác-với-câu-lệnh](#4-thao-tác-với-câu-lệnh)

[5-thao-tác-với-toán-hạng](#5-thao-tác-với-toán-hạng)

[6-giả-lập-ida](#6-giả-lập-ida)

[7-thao-tác-với-tham-chiếu](#7-thao-tác-với-tham-chiếu)

---

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

### 6. Giả lập IDA

Để lấy câu lệnh dạng đối tượng (inst_t) tại một địa chỉ ta có thể sử dụng lệnh sau

```
inst = idautils.DecodeInstruction(idc.here())

# Trong đó đối tượng inst sẽ có các thuộc tính như sau
inst.itype : đây là số nguyên biểu diễn loại lệnh. Các opcode khác nhau có cùng itype và do đó opcode != itype .
inst.size : đây là kích thước của lệnh được giải mã.
inst.Operands[] : đây là mảng bắt đầu từ số 0 chứa thông tin toán hạng.
inst.Op1 .. OpN : đây là các bí danh dựa trên 1 trong mảng Toán hạng .
inst.ea : địa chỉ tuyến tính của lệnh được giải mã.
```

Bạn có thể tự hỏi mối quan hệ giữa opcode và itype của nó là gì ? Câu trả lời rất đơn giản. Trong IDA, mô-đun bộ xử lý của cơ sở dữ liệu mở chịu trách nhiệm điền vào trường itype dựa trên opcode. Trong IDA SDK, bạn có thể tìm thấy tệp tiêu đề có tên là **allins.hpp** . Tệp tiêu đề này chứa các enum cho tất cả các mô-đun bộ xử lý được hỗ trợ cùng với các thành viên enum cho mỗi lệnh được hỗ trợ:

```
// Trích đoạn từ allins.hpp
// Kiểu x86/x64
liệt kê
{
NN_null = 0,             // Hoạt động không xác định
NN_aaa,                  // Điều chỉnh ASCII sau khi cộng
NN_aad,                  // ASCII Điều chỉnh AX trước khi chia
NN_aam,                  // ASCII Điều chỉnh AX sau khi Nhân
NN_aas,                  // ASCII Điều chỉnh AL sau khi trừ
.
.
.
NN_jz,                   // Nhảy nếu bằng 0 (ZF=1)
NN_jmp,                  // Nhảy
NN_jmpfi,                // Nhảy xa gián tiếp
NN_jmpni,                // Nhảy gần gián tiếp
NN_jmpshort,             // Nhảy ngắn (không sử dụng)
NN_lahf,                 // Tải cờ vào thanh ghi AH
.
.
.
// Hướng dẫn giả Pentium III
NN_cmpeqps,              // EQ so sánh FP đơn được đóng gói
NN_cmpltps,              // Đóng gói Single-FP So sánh LT
NN_cmpleps,              // Đóng gói Single-FP So sánh LE
NN_cmpunordps,           // Đóng gói Single-FP So sánh UNORD
.
.
.
}
```

```
# Example
# .text:00402085 74 09 jz short loc_402090
inst = idautils.DecodeInstruction(0x402085)
print("YES" if inst.itype == idaapi.NN_jz else "NO")
```
Người ta có thể kiểm tra trực quan lệnh được giải mã bằng cách so sánh với một trong  các hằng số idaapi.NN_xxxx .

Đối với toán hạng, người ta có thể truy cập chúng thông qua inst.Operands[] hoặc inst.OpN . Để có được số toán hạng được lệnh giải mã sử dụng, bạn không nên dựa vào độ dài của mảng Operands vì nó sẽ luôn giải quyết thành  UA_MAXOP == 8 (xem ida.hpp ). Thay vào đó, hãy lặp lại từng toán hạng và xem loại của nó có phải là o_void hay không .

Toán hạng lệnh được định nghĩa bằng cách sử dụng kiểu cấu trúc op_t được xác định trong tệp tiêu đề ua.hpp .

```
op.flags : cờ toán hạng.
op.dtype : kiểu toán hạng. Một trong các hằng số dt_xxx . Người ta có thể sử dụng trường này để cho biết kích thước của toán hạng (1 == dt_byte , 2 == dt_word , v.v.).
op.type : kiểu toán hạng. Một trong các hằng số o_xxx .
specflag1 .. specflag4 : cờ cụ thể của bộ xử lý.    
op.reg : thanh ghi( o_reg ).
op.phrase : thanh ghi chỉ mục có chức năng truy cập bộ nhớ các toán hạng ( o_phrase ).
op.value : giá trị tức thời (o_imm) hoặc độ dịch chuyển bên ngoài ( o_displ ).
op.addr : địa chỉ bộ nhớ được toán hạng sử dụng ( o_mem , o_far , o_displ , o_near ).

# Các kiểu toán hạng
o_void : không có toán hạng nào hiện diện.
o_reg : toán hạng là một thanh ghi (al, ax,es,ds…).
o_mem : tham chiếu bộ nhớ trực tiếp (DATA).
o_phrase : Tham chiếu bộ nhớ [Reg cơ sở + Reg chỉ mục].
o_displ : bộ nhớ Reg [Reg cơ sở + Reg chỉ mục + Độ dịch chuyển].
o_imm : giá trị tức thời.
o_far : Địa chỉ xa tức thời (CODE).
o_near : Địa chỉ gần nhất (CODE).
o_idpspec0 ..  o_idpspec5 : cờ cụ thể của bộ xử lý.
```

Khi kiểu toán hạng là o_reg hoặc o_phrase , thì các giá trị op.reg / op.phrase chứa giá trị enum của thanh ghi. Giống như thuật ngữ NN_xxx , IDA SDK cũng cung cấp tên hằng số thanh ghi và giá trị của chúng; tuy nhiên điều này chỉ đúng với mô-đun bộ xử lý x86/x64. Sau đây là một đoạn trích từ tệp tiêu đề intel.hpp :

Ví dụ phân tách hoàn tianf một lệnh

```
# .text:0040106F 35 90 8D 28 DA xor     eax, 0DA288D90h
out = ''
inst = idautils.DecodeInstruction(0x40106F)
out += "XOR "     if inst.itype == idaapi.NN_xor else ""
out += "EAX"      if (inst.Op1.type == idaapi.o_reg and inst.Op1.reg == 0) else ""
out += ", 0x%08X" % inst.Op2.value if (inst.Op2.type == idaapi.o_imm) else ""
print(out)
```

Ví dụ để tìm một pattern code như sau

```
\def scope_challenge_function(func_ea):
    f = idaapi.get_func(func_ea)
    if f is None:
        return (False, "No function at address!")
        
    emu_start, emu_end = f.startEA, f.endEA
    
    ea = emu_start
    #    
    # Find the start of the emulation pattern
    #
    stage = 0
    while ea <= emu_end:
        inst = idautils.DecodeInstruction(ea)
        if inst is None:
            return (False, "Could not decode")
            
        # Advance to next instruction
        ea += inst.size
        
        # mov (eax|edx), [ebp+?]
        if (inst.itype == idaapi.NN_mov) and (inst.Operands[0].type == idaapi.o_reg) and \
           (inst.Operands[1].type == idaapi.o_displ) and (inst.Operands[1].phrase == REG_EBP):
            # mov eax, [ebp+8]
            if (stage == 0) and (inst.Operands[0].reg == REG_EAX) and (inst.Operands[1].addr == 8):
                stage = 1
            # mov edx, [ebp+0xC]
            elif (stage == 1) and (inst.Operands[0].reg == REG_EDX) and (inst.Operands[1].addr == 0xC):
                stage = 2
                emu_start = ea
        elif (stage == 2) and (inst.itype == idaapi.NN_popa):
            # Let's decode backwards twice and double check the pattern
            ea2 = idc.PrevHead(ea)
            
            # Disassemble backwards
            for _ in range(0, 2):
                ea2 = idc.PrevHead(ea2)
                inst = idautils.DecodeInstruction(ea2)
                if (inst.itype == idaapi.NN_mov) and (inst.Op1.type == idaapi.o_displ) and \
                   (inst.Op1.reg == 5):
                    if inst.Op2.reg == 2 and stage == 2:
                        stage = 3
                    elif inst.Op2.reg == 0 and stage == 3:
                        stage = 4
                        emu_end = ea2
                        break
                   
            break
            
       
    if stage != 4:
        return (False, "Could not find markers")
            
    return (True, (emu_start, emu_end))
```

Một ví dụ khác 

```
def emulate_challenge_function(info, c1, c2, dbg = False):
    emu_start, emu_end = info
    if dbg:
        print("Emulating from %x to %x (%d, %d)" % (emu_start, emu_end, c1, c2))
    # Reset registers    
    regs = { 
      REG_EAX: c1,
      REG_EDX: c2
    }
    
    def get_opr_val(inst, regs):
        if inst.Op2.type == o_imm:
            return (True, inst.Op2.value)
        elif inst.Op2.type == idaapi.o_reg:
            return (True, regs[inst.Op2.reg])
        else:
            return (False, 0)
            
    ea = emu_start
    while ea < emu_end:
        out = ">%x: " % ea
        ok = True
        inst = idautils.DecodeInstruction(ea)
        ea += inst.size
        if inst.itype == idaapi.NN_not:
            out += "NOT"
            regs[inst.Op1.reg] = ~regs.get(inst.Op1.reg, 0) & 0xffffffff
        elif inst.itype == idaapi.NN_dec and inst.Op1.type == idaapi.o_reg:
            out += "DEC"        
            regs[inst.Op1.reg] = (regs.get(inst.Op1.reg, 0) - 1) & 0xffffffff
        elif inst.itype == idaapi.NN_inc and inst.Op1.type == idaapi.o_reg:
            out += "INC"        
            regs[inst.Op1.reg] = (regs.get(inst.Op1.reg, 0) + 1) & 0xffffffff
        elif inst.itype == idaapi.NN_xor:
            ok, val = get_opr_val(inst, regs)
            regs[inst.Op1.reg] = (regs.get(inst.Op1.reg, 0) ^ val) & 0xffffffff
            out += "XOR %08X" % val
        elif inst.itype == idaapi.NN_sub:
            ok, val = get_opr_val(inst, regs)
            regs[inst.Op1.reg] = (regs.get(inst.Op1.reg, 0) - val) & 0xffffffff
            out += "SUB %08X" % val
        elif inst.itype == idaapi.NN_add:
            ok, val = get_opr_val(inst, regs)
            regs[inst.Op1.reg] = (regs.get(inst.Op1.reg, 0) + val) & 0xffffffff
            out += "ADD %08X" % val
        else:
            ok = False
        # Dump registers
        for k, v in regs.items():
            out += (" [%s: %08X] " % (REG_NAMES.get(k, "%x" % k), v))
        if not ok:
            return (False, "Emulation failed at %08X" % ea)
        if dbg:            
            print(out)
    
    return (True, (regs[REG_EDX] << 32) | regs[REG_EAX])
```

Khi hàm bắt đầu, nó sẽ điền các giá trị ban đầu của các thanh ghi vào từ điển regs . Chúng ta sử dụng op.reg làm khóa vào từ điển đó. Bất kỳ thanh ghi nào chưa được khởi tạo sẽ chứa giá trị bằng không. Sau đó, hàm mô phỏng sẽ nhập một vòng lặp và giải mã từng lệnh. Đối với mỗi lệnh, nó sẽ kiểm tra loại lệnh (để biết thao tác nào cần mô phỏng) và các toán hạng của lệnh (để biết cách lấy các giá trị cần thiết). Khi kết thúc vòng lặp, một giá trị 64 bit sẽ được trả về.

Chúng ta có thể xác minh xem trình giả lập có chính xác hay không bằng cách so sánh kết quả trả về từ trình giả lập với kết quả chúng ta đã thu thập trước đó:

```
for i in range(0, challenge_funcs_tbl_size):
    func = idc.Dword(challenge_funcs_tbl +  i * 4)
    
    ok, info = scope_challenge_function(func)
    if ok:
        ok, val = emulate_challenge_function(info, 123, 456, dbg)
        if (val != RESULTS[i]):
            print("Mistmatch #%d: %16X vs %16X" % (i, val, RESULTS[i]))
            break
        
    else:
        print("Failed to scope challenge function #%d" % i)
```

### 7. Thao tác với tham chiếu

Xrefs trong IDApython được sử dụng để xử lý các phép tham chiếu và cross-reference (Xrefs) trong mã nguồn của chương trình phân tích. Dưới đây là một số hàm Xrefs thường được sử dụng và cách sử dụng:

Duyệt tham chiếu tới một địa chỉ

```
for xref in idautils.XrefsTo(ea):
    print(f"From: {hex(xref.frm)}, To: {hex(xref.to)}")

for xref in XrefsFrom(ea):
    print(f"From: {hex(xref.frm)}, To: {hex(xref.to)}")
```

Lấy địa chỉ đầu tiên tham chiếu đến ea

```
cref = idc.get_first_cref_to(ea)
if cref != idaapi.BADADDR:
    print(f"First code reference to {hex(ea)} is from {hex(cref)}")
```

Lấy địa chỉ tiếp theo tham chiếu đến ea

```
next_cref = idc.get_next_cref_to(ea, current_cref)
if next_cref != idaapi.BADADDR:
    print(f"Next code reference to {hex(ea)} is from {hex(next_cref)}")
```

Lấy địa chỉ đầu tiên mà địa chỉ ea tham chiếu tới

```
cref = idc.get_first_cref_from(ea)
if cref != idaapi.BADADDR:
    print(f"First code reference from {hex(ea)} is to {hex(cref)}")

# Địa chỉ tiếp theo mà ea tham chiếu tới sử dụng lệnh sau

next_cref = get_next_cref_from(ea, current_cref)
if next_cref != BADADDR:
    print(f"Next code reference from {hex(ea)} is to {hex(next_cref)}")
```
---
#### Các Thuộc Tính của Đối Tượng Xrefs

***from***
```
Mô tả: Địa chỉ (Effective Address - EA) từ đó tham chiếu được thực hiện.
Loại: int
Ví dụ: xref.from sẽ trả về địa chỉ nguồn của tham chiếu.
```
***to***
```
Mô tả: Địa chỉ (EA) mà tham chiếu trỏ tới.
Loại: int
Ví dụ: xref.to sẽ trả về địa chỉ đích của tham chiếu.
```
***type***
```
Mô tả: Loại tham chiếu. Các loại tham chiếu có thể bao gồm mã, dữ liệu, nhảy, gọi hàm, và các loại tham chiếu khác.
Loại: int
Ví dụ: xref.type sẽ trả về kiểu tham chiếu. Bạn có thể so sánh với các hằng số như XREF_DATA, XREF_CODE, XREF_CALL, v.v.
```
***flags***
```
Mô tả: Cờ (flag) cho biết loại tham chiếu, có thể bao gồm các flag như XREF_DATA, XREF_CODE, XREF_JUMP, v.v.
Loại: int
Ví dụ: xref.flags sẽ trả về cờ của tham chiếu.
```

----
#### Các loại cờ của đối tượng xrefs
Khi làm việc với các hàm Xrefs, bạn có thể sử dụng các flag để chỉ định loại tham chiếu bạn quan tâm.

***1. XREF_DATA***
```
Mô tả: Tham chiếu dữ liệu (data reference).
Flag: 0x0001
```
***2. XREF_CODE***
```
Mô tả: Tham chiếu mã (code reference).
Flag: 0x0002
```
***3. XREF_USER***
```
Mô tả: Tham chiếu do người dùng tạo (user-defined reference).
Flag: 0x0004
```
***4. XREF_JUMP***
```
Mô tả: Tham chiếu nhảy (jump reference).
Flag: 0x0008
```
***5. XREF_CALL***
```
Mô tả: Tham chiếu gọi hàm (call reference).
Flag: 0x0010
```
***6. XREF_DUMMY***
```
Mô tả: Tham chiếu giả (dummy reference) – thường không quan trọng trong phân tích thông thường.
Flag: 0x0020
```
***7. XREF_TYPE_MASK***
```
Mô tả: Mask để lọc các loại tham chiếu.
Flag: 0x003F
```

### 8. Debug hook với IDApython
Tạo một file Python mới để chứa script. Dưới đây là ví dụ về một script đơn giản để thiết lập và sử dụng debug hook.

```
import idaapi

class MyDebugHook(idaapi.DBG_Hooks):
    def __init__(self):
        super(MyDebugHook, self).__init__()
    
    def dbg_bpt(self, tid, ea):
        print(f"Breakpoint hit at address: {hex(ea)}")
        return idaapi.DBG_CONTINUE
    
    def dbg_step_into(self, tid):
        print(f"Stepped into thread: {tid}")
        return idaapi.DBG_CONTINUE

    def dbg_step_over(self, tid):
        print(f"Stepped over thread: {tid}")
        return idaapi.DBG_CONTINUE

    def dbg_step_out(self, tid):
        print(f"Stepped out of thread: {tid}")
        return idaapi.DBG_CONTINUE

    def dbg_ret(self, tid):
        print(f"Function return in thread: {tid}")
        return idaapi.DBG_CONTINUE

    def dbg_exception(self, tid, exception):
        print(f"Exception in thread {tid}: {exception}")
        return idaapi.DBG_CONTINUE

# Initialize and hook
debug_hook = MyDebugHook()
debug_hook.hook()
print("Debug hook installed")
```