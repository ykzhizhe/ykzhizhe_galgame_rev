想了想还是先把文案写出来，md的后面添加就行

大家好啊，第一次做这种视频，今天讲讲krkr引擎的cxdec插件逆向，也就是俗称的hxv4

这期视频的着重点在文件名哈希和路径哈希（file/path hash）

这个插件的特点是，路径/文件名全部哈希，也就是说正常解包下来的东西，文件名完全被哈希了，有因为哈希本身的原因，导致文件名/路径名不可以逆，只能通过猜测的方式来还原

就目前来说，常见的还原方式：
    1：krkrdump：直接dump出原本的文件，但是展鸿佬把这个删了，而且他本身也被DMCA了，所以大概是不能讲的（？）#TODO：黑化处理
    2：封包内其他文件信息还原：我们只是不能还原文件名，内容都是正常的，所以，部分文件的数据是有的，常见的有!scnlist.txt这个文件，包含了所有.scn文件的文件名，直接喂给哈希算法，然后还原就行
    3：常量硬猜：根据命名规则硬猜，比如miyako_1.scn等等，常量的话，START.TJS啊，SYSTEM啊，等等，很多东西都是写死的，直接去抄那个krkrz就行

以上方法都有些许缺点：
    1：krkrdump：你得跑完整个游戏，因为是dump的形式，可能会有文件读不到，虽然读不到的文件大概率不影响游戏本身就是 #TODO：黑化处理
    2：一样的，总有文件名不在这里面的，虽然之后漏掉一点，但是还是会漏，而且，并不是所有文件都是.txt格式的，也有scn/tjs格式等等，对于tjs2100（也就是编译的.tjs）的话，直接读是不行的，scn能还原或者直接是明文倒是还好，还原不了的话看操作可能要人工去看，当然，tjs2100和scn都是在某些程度上可以还原的（也就是直接读到字符串），但是有没有些东西不在这里面呢？可能会有？
    3：硬猜能猜多少？也就是肯定会有遗漏

讲讲怎么汉化：
    1：完整提取文件，按照原本逻辑封包回去，这个是最好理解的方法，krkrz本身就支持UTF-8，但是弊端是太麻烦了，但是就从实现来说，不是做不到，索引表/文件名和文件的解密都能还原，但是一个一个写逻辑未免有点变态，虽然造个轮子可以很快的跑
    2：首先感谢一下，真的很感谢，magalumina的补丁作者，这个东西是在他的基础上修改的，在https://github.com/ykzhizhe/krkr_cxdec_version_patch，原理我就不讲了，反正使用方法就是把这个东西扔进游戏根目录文件夹，然后游戏会优先读取patch.xp3，这个应该没有重复造轮子，我没有查到相关的开源项目，应该确实是没有。对了补充一下，patch.xp3不需要加密，但是需要还原文件名

好，讲了大概1000多个字，废话也讲完了，也可以开始正片了。

首先先明确一点，这个东西本质上是一个插件，也就是和知名的AlphaMovie/wuvorbis等等插件一样的东西，只不过它的加载方式不太相同，其他的插件是直接扔在plugin文件夹下，而hxv4是被游戏exe先释放出来，然后再加载的，释放然后加载就不展示了，只需要知道这个插件会被扔在
## %temp%/krkr_[a-z0-9]{12}_[a-z0-9]{6,7}_[a-z0-9]{4,5}$
里面，另外dll的文件名是哈希的，也即是不固定，但是在游戏运行中是固定的,也就是说可以直接挪一个出来，这个找出的过程在视频中演示吧

# TODO 照片1
# TODO 照片2

那么这个就是要找到插件，要找的文件名哈希/路径哈希的函数都在里面，但是dll很大，一点一点找显得不太可能。对于krkr的插件，都是用的V2Link/V2UnLink的方式来进行的，也就是说，抛开编译器自己的辅助函数，被编写的函数一定在V2link函数开始

找到导入表，V2Link和V2Unlink都在这里，先看看V2Link,是比较标准的格式，从+14B80开始看：
    1：我们看到了大量的+16420，不难判断其是一个throw error函数，一般来说，不会运行到这里的，所以直接标注然后不管：m_throw_error
    2：一些debug字符，其实意义不大，比较不是我们分析的东西
    3：最后return了一个+FAE0和+4C60，这两个函数都很庞大，很轻松就可以知道要分析的都在里面（这不废话吗），标注命名：m_init1/m_init2

按照顺序，先看init1，很轻松就看到了："bootStrap", "checkSignature", "System", "isExistentStorageNoSearchNoNormalize", "parseArchiveIndex", "archiveUniqueKey"等字符串

再看init2，"unmountAll", "unmount" ... "getHashes", "getFile" ... "pathHash", "fileHash", "CompoundStorageMedia", "Storages" ......
今天分析的的是Path/File哈希，也就是"pathHash", "fileHash" 这一块，后面依次还有"CompoundStorageMedia", "Storages"这两个

先分析，"pathHash", "fileHash"这两个，可以很明显的看到



```c
p_m_arc_pathHash = m_arc_pathHash;    //这里
  if ( !tTJSString::tTJSString_const_tjs_char____ )
  {
    _tTJSString::tTJSString(const_tjs_char__)__14 = m_throw_error(aTtjsstringTtjs_2);// "tTJSString::tTJSString(const tjs_char *)"
    tTJSString::tTJSString_const_tjs_char____ = _tTJSString::tTJSString(const_tjs_char__)__14;
  }
  _tTJSString::tTJSString(const_tjs_char__)__14(v110, L"pathHash");
  _tTJSString::tTJSString(const_tjs_char__)__15 = tTJSString::tTJSString_const_tjs_char____;
  LOBYTE(v113) = 14;
  p_m_arc_fileHash = m_arc_fileHash;        //这里
  if ( !tTJSString::tTJSString_const_tjs_char____ )
  {
    _tTJSString::tTJSString(const_tjs_char__)__15 = m_throw_error(aTtjsstringTtjs_2);// "tTJSString::tTJSString(const tjs_char *)"
    tTJSString::tTJSString_const_tjs_char____ = _tTJSString::tTJSString(const_tjs_char__)__15;
  }
  _tTJSString::tTJSString(const_tjs_char__)__15(v97, L"fileHash");
  _tTJSString::tTJSString(const_tjs_char__)__16 = tTJSString::tTJSString_const_tjs_char____;
  LOBYTE(v113) = 15;
  p_m_arc_Storages2 = m_arc_Storages2;
  p_m_arc_CompoundStorageMedia = m_arc_CompoundStorageMedia;
  if ( !tTJSString::tTJSString_const_tjs_char____ )
  {
    _tTJSString::tTJSString(const_tjs_char__)__16 = m_throw_error(aTtjsstringTtjs_2);// "tTJSString::tTJSString(const tjs_char *)"
    tTJSString::tTJSString_const_tjs_char____ = _tTJSString::tTJSString(const_tjs_char__)__16;
  }
  _tTJSString::tTJSString(const_tjs_char__)__16(v95, L"CompoundStorageMedia");
  _tTJSString::tTJSString(const_tjs_char__)__17 = tTJSString::tTJSString_const_tjs_char____;
  LOBYTE(v113) = 16;
  if ( !tTJSString::tTJSString_const_tjs_char____ )
  {
    _tTJSString::tTJSString(const_tjs_char__)__17 = m_throw_error(aTtjsstringTtjs_2);// "tTJSString::tTJSString(const tjs_char *)"
    tTJSString::tTJSString_const_tjs_char____ = _tTJSString::tTJSString(const_tjs_char__)__17;
  }
  _tTJSString::tTJSString(const_tjs_char__)__17(v96, L"Storages");
```

除了本来就有的filehash/pathhash，其他需要关注的有:
  Storages->p_m_arc_Storages2 = m_arc_Storages2;
  CompoundStorageMedia->p_m_arc_CompoundStorageMedia = m_arc_CompoundStorageMedia;

优先分析一下pathhash：

```c
int __thiscall m_arc_pathHash(void *this, int a2, int a3)
{
  int (__stdcall *_tTJSVariantType_tTJSVariant::Type()_)(int); // eax
  int v6; // esi
  void (__stdcall *_tTJSString::tTJSString(const_tTJSVariant_&)_)(_BYTE *, int); // eax
  int *v8; // eax
  void (__stdcall *_tTJSVariant::tTJSVariant(const_tTJSVariant_&)_)(_BYTE *, _BYTE *); // eax
  void (__stdcall *_tTJSVariant_&_tTJSVariant::operator__(const_tTJSVariant_&)_)(int, _BYTE *); // eax
  void (__stdcall *_tTJSVariant::__tTJSVariant()_)(_BYTE *); // eax
  void (__stdcall *_tTJSVariant::__tTJSVariant()__1)(_BYTE *); // eax
  int v13; // esi
  void (__stdcall *_void_tTJSVariantOctet::Release()_)(int); // eax
  void (__stdcall *_tTJSString::__tTJSString()_)(_BYTE *); // eax
  _BYTE v16[12]; // [esp+Ch] [ebp-28h] BYREF
  _BYTE v17[12]; // [esp+18h] [ebp-1Ch] BYREF
  _BYTE v18[4]; // [esp+24h] [ebp-10h] BYREF
  int v19; // [esp+30h] [ebp-4h]

  _tTJSVariantType_tTJSVariant::Type()_ = tTJSVariantType_tTJSVariant::Type___;
  if ( !tTJSVariantType_tTJSVariant::Type___ )
  {
    _tTJSVariantType_tTJSVariant::Type()_ = m_throw_error(aTtjsvarianttyp);// "tTJSVariantType tTJSVariant::Type()"
    tTJSVariantType_tTJSVariant::Type___ = _tTJSVariantType_tTJSVariant::Type()_;
  }
  if ( _tTJSVariantType_tTJSVariant::Type()_(a3) != 2 )
    return 0xFFFFFC15;
  v6 = a2;
  if ( a2 )
  {
    _tTJSString::tTJSString(const_tTJSVariant_&)_ = tTJSString::tTJSString_const_tTJSVariant____;
    if ( !tTJSString::tTJSString_const_tTJSVariant____ )
    {
      _tTJSString::tTJSString(const_tTJSVariant_&)_ = m_throw_error(aTtjsstringTtjs_5);// "tTJSString::tTJSString(const tTJSVariant &)"
      tTJSString::tTJSString_const_tTJSVariant____ = _tTJSString::tTJSString(const_tTJSVariant_&)_;
    }
    _tTJSString::tTJSString(const_tTJSVariant_&)_(v18, a3);
    v19 = 0;
    v8 = m_arc_pathHash_runfrist(this, &a2, v18);
    LOBYTE(v19) = 1;
    m_arc_Hash_runsecond(v8, v16);
    _tTJSVariant::tTJSVariant(const_tTJSVariant_&)_ = tTJSVariant::tTJSVariant_const_tTJSVariant____;
    LOBYTE(v19) = 2;
    if ( !tTJSVariant::tTJSVariant_const_tTJSVariant____ )
    {
      _tTJSVariant::tTJSVariant(const_tTJSVariant_&)_ = m_throw_error(aTtjsvariantTtj);// "tTJSVariant::tTJSVariant(const tTJSVariant &)"
      tTJSVariant::tTJSVariant_const_tTJSVariant____ = _tTJSVariant::tTJSVariant(const_tTJSVariant_&)_;
    }
    _tTJSVariant::tTJSVariant(const_tTJSVariant_&)_(v17, v16);
    _tTJSVariant_&_tTJSVariant::operator__(const_tTJSVariant_&)_ = tTJSVariant___tTJSVariant::operator___const_tTJSVariant____;
    LOBYTE(v19) = 3;
    if ( !tTJSVariant___tTJSVariant::operator___const_tTJSVariant____ )
    {
      _tTJSVariant_&_tTJSVariant::operator__(const_tTJSVariant_&)_ = m_throw_error(aTtjsvariantTtj_2);// "tTJSVariant & tTJSVariant::operator =(const tTJSVariant &)"
      tTJSVariant___tTJSVariant::operator___const_tTJSVariant____ = _tTJSVariant_&_tTJSVariant::operator__(const_tTJSVariant_&)_;
    }
    _tTJSVariant_&_tTJSVariant::operator__(const_tTJSVariant_&)_(v6, v17);
    _tTJSVariant::__tTJSVariant()_ = tTJSVariant::__tTJSVariant___;
    LOBYTE(v19) = 2;
    if ( !tTJSVariant::__tTJSVariant___ )
    {
      _tTJSVariant::__tTJSVariant()_ = m_throw_error(aTtjsvariantTtj_0);// "tTJSVariant::~ tTJSVariant()"
      tTJSVariant::__tTJSVariant___ = _tTJSVariant::__tTJSVariant()_;
    }
    _tTJSVariant::__tTJSVariant()_(v17);
    _tTJSVariant::__tTJSVariant()__1 = tTJSVariant::__tTJSVariant___;
    LOBYTE(v19) = 1;
    if ( !tTJSVariant::__tTJSVariant___ )
    {
      _tTJSVariant::__tTJSVariant()__1 = m_throw_error(aTtjsvariantTtj_0);// "tTJSVariant::~ tTJSVariant()"
      tTJSVariant::__tTJSVariant___ = _tTJSVariant::__tTJSVariant()__1;
    }
    _tTJSVariant::__tTJSVariant()__1(v16);
    v13 = a2;
    LOBYTE(v19) = 0;
    if ( a2 )
    {
      _void_tTJSVariantOctet::Release()_ = void_tTJSVariantOctet::Release___;
      if ( !void_tTJSVariantOctet::Release___ )
      {
        _void_tTJSVariantOctet::Release()_ = m_throw_error(aVoidTtjsvarian_0);// "void tTJSVariantOctet::Release()"
        void_tTJSVariantOctet::Release___ = _void_tTJSVariantOctet::Release()_;
      }
      _void_tTJSVariantOctet::Release()_(v13);
    }
    _tTJSString::__tTJSString()_ = tTJSString::__tTJSString___;
    a2 = 0;
    v19 = -1;
    if ( !tTJSString::__tTJSString___ )
    {
      _tTJSString::__tTJSString()_ = m_throw_error(aTtjsstringTtjs_0);// "tTJSString::~ tTJSString()"
      tTJSString::__tTJSString___ = _tTJSString::__tTJSString()_;
    }
    _tTJSString::__tTJSString()_(v18);
  }
  return 0;
}
```

一眼看过去很多除错的debug函数，需要看的不多：

    v19 = 0;
    v8 = m_arc_pathHash_runfrist(this, &a2, v18);
    LOBYTE(v19) = 1;
    m_arc_Hash_runsecond(v8, v16);
    _tTJSVariant::tTJSVariant(const_tTJSVariant_&)_ = tTJSVariant::tTJSVariant_const_tTJSVariant____;

这两个函数目前没有进行分析，但是知道先后顺序，先姑且命名为：m_arc_pathHash_runfrist/m_arc_pathHash_runsecond

```c
int *__thiscall m_arc_PathandFileHash_runfrist_next(char *this, int *a2, int a3, int a4)
{
  void (__stdcall *_tTJSVariant::tTJSVariant()_)(_BYTE *); // eax
  unsigned __int8 (__stdcall *_bool_tTJSString::IsEmpty()_const_)(char *); // eax
  char *v1; // esi
  int (__stdcall *_tTJSVariantOctet___tTJSVariant::AsOctetNoAddRef()_const_)(_BYTE *); // eax
  int v9; // esi
  void (__stdcall *_void_tTJSVariantOctet::AddRef()_)(int); // eax
  void (__stdcall *_tTJSVariant::__tTJSVariant()_)(_BYTE *); // eax
  _BYTE v13[12]; // [esp+Ch] [ebp-1Ch] BYREF
  int v14; // [esp+18h] [ebp-10h]
  int v15; // [esp+24h] [ebp-4h]

  v14 = 0;
  _tTJSVariant::tTJSVariant()_ = tTJSVariant::tTJSVariant___;
  if ( !tTJSVariant::tTJSVariant___ )
  {
    _tTJSVariant::tTJSVariant()_ = m_throw_error(aTtjsvariantTtj_3);// "tTJSVariant::tTJSVariant()"
    tTJSVariant::tTJSVariant___ = _tTJSVariant::tTJSVariant()_;
  }
  _tTJSVariant::tTJSVariant()_(v13);
  _bool_tTJSString::IsEmpty()_const_ = bool_tTJSString::IsEmpty___const_;
  v15 = 1;
  if ( !bool_tTJSString::IsEmpty___const_ )
  {
    _bool_tTJSString::IsEmpty()_const_ = m_throw_error(aBoolTtjsstring_0);// "bool tTJSString::IsEmpty() const"
    bool_tTJSString::IsEmpty___const_ = _bool_tTJSString::IsEmpty()_const_;
  }
  v1 = this + 16;
  if ( _bool_tTJSString::IsEmpty()_const_(v1) )
    // 动态调试发现：
    v1 = 0;
  (*(*a3 + 4))(a3, v13, a4, v1);                // 未知函数（暂时）
                                                // 
  _tTJSVariantOctet___tTJSVariant::AsOctetNoAddRef()_const_ = tTJSVariantOctet___tTJSVariant::AsOctetNoAddRef___const_;
  if ( !tTJSVariantOctet___tTJSVariant::AsOctetNoAddRef___const_ )
  {
    _tTJSVariantOctet___tTJSVariant::AsOctetNoAddRef()_const_ = m_throw_error(aTtjsvariantoct);// "tTJSVariantOctet * tTJSVariant::AsOctetNoAddRef() const"
    tTJSVariantOctet___tTJSVariant::AsOctetNoAddRef___const_ = _tTJSVariantOctet___tTJSVariant::AsOctetNoAddRef()_const_;
  }
  v9 = _tTJSVariantOctet___tTJSVariant::AsOctetNoAddRef()_const_(v13);
  *a2 = v9;
  if ( v9 )
  {
    _void_tTJSVariantOctet::AddRef()_ = void_tTJSVariantOctet::AddRef___;
    if ( !void_tTJSVariantOctet::AddRef___ )
    {
      _void_tTJSVariantOctet::AddRef()_ = m_throw_error(aVoidTtjsvarian);// "void tTJSVariantOctet::AddRef()"
      void_tTJSVariantOctet::AddRef___ = _void_tTJSVariantOctet::AddRef()_;
    }
    _void_tTJSVariantOctet::AddRef()_(v9);
  }
  _tTJSVariant::__tTJSVariant()_ = tTJSVariant::__tTJSVariant___;
  v14 = 1;
  LOBYTE(v15) = 0;
  if ( !tTJSVariant::__tTJSVariant___ )
  {
    _tTJSVariant::__tTJSVariant()_ = m_throw_error(aTtjsvariantTtj_0);// "tTJSVariant::~ tTJSVariant()"
    tTJSVariant::__tTJSVariant___ = _tTJSVariant::__tTJSVariant()_;
  }
  _tTJSVariant::__tTJSVariant()_(v13);
  return a2;
}
```

暂且分析一下：核心调用只有：(*(*a3 + 4))(a3, v13, a4, v1);

对于这个整体传入参数调用(*a3+4)
```
.text:66886060                 mov     ecx, [ebp+arg_4]
.text:66886063                 push    esi
.text:66886064                 push    [ebp+arg_8]
.text:66886067                 mov     eax, [ecx] // eax被赋值，也就是要去查看ecx的地址有什么
.text:66886069                 lea     edx, [ebp+var_1C]
.text:6688606C                 push    edx
.text:6688606D                 call    dword ptr [eax+4] //eax+4 a3即为eax很好理解
```
对于这个a3整体，我们是不知道的，需要动调，先看汇编

动调发现，call的地址是：668969F0（+159F0）

此时函数反编译：
```c
int __userpurge m_Pathhash_Or_Filehash_init@<eax>(int a1@<ecx>, int a2@<edi>, int a3@<esi>, int a4, int a5, int a6)
{
  int (__stdcall *_tjs_int_tTJSString::length()_const_)(int, int, int); // eax
  int v7; // edi
  __int64 (__stdcall *_const_tjs_char___tTJSString::c_str()_const_)(int); // eax
  unsigned __int64 v9; // rax
  int (__stdcall *_tjs_int_tTJSString::length()_const__1)(int); // eax
  int v11; // edi
  __int64 (__stdcall *_const_tjs_char___tTJSString::c_str()_const__1)(int); // eax
  unsigned __int64 v13; // rax
  unsigned int n8; // [esp-4h] [ebp-54h]
  _DWORD v16[20]; // [esp+0h] [ebp-50h] BYREF

  n8 = *(a1 + 8);
  qmemcpy(v16, "uespemosmodnarodarenegylsetybdet", 32); //这是一个key，不过先不用管
  m_Pathhash_Or_Filehash_run(v16, *(a1 + 4), n8);// a1+4 就是v16
  _tjs_int_tTJSString::length()_const_ = tjs_int_tTJSString::length___const_;
  if ( !tjs_int_tTJSString::length___const_ )
  {
    _tjs_int_tTJSString::length()_const_ = m_throw_error(aTjsIntTtjsstri);// "tjs_int tTJSString::length() const"
    tjs_int_tTJSString::length___const_ = _tjs_int_tTJSString::length()_const_;
  }
  v7 = _tjs_int_tTJSString::length()_const_(a5, a2, a3);
  _const_tjs_char___tTJSString::c_str()_const_ = const_tjs_char___tTJSString::c_str___const_;
  if ( !const_tjs_char___tTJSString::c_str___const_ )
  {
    _const_tjs_char___tTJSString::c_str()_const_ = m_throw_error(aConstTjsCharTt);// "const tjs_char * tTJSString::c_str() const"
    const_tjs_char___tTJSString::c_str___const_ = _const_tjs_char___tTJSString::c_str()_const_;
  }
  v9 = _const_tjs_char___tTJSString::c_str()_const_(a5);
  m_Pathhash_Or_Filehash_run2(v9, v16, v9, 2 * v7);
  if ( a6 )
  {
    _tjs_int_tTJSString::length()_const__1 = tjs_int_tTJSString::length___const_;
    if ( !tjs_int_tTJSString::length___const_ )
    {
      _tjs_int_tTJSString::length()_const__1 = m_throw_error(aTjsIntTtjsstri);// "tjs_int tTJSString::length() const"
      tjs_int_tTJSString::length___const_ = _tjs_int_tTJSString::length()_const__1;
    }
    v11 = _tjs_int_tTJSString::length()_const__1(a6);
    _const_tjs_char___tTJSString::c_str()_const__1 = const_tjs_char___tTJSString::c_str___const_;
    if ( !const_tjs_char___tTJSString::c_str___const_ )
    {
      _const_tjs_char___tTJSString::c_str()_const__1 = m_throw_error(aConstTjsCharTt);// "const tjs_char * tTJSString::c_str() const"
      const_tjs_char___tTJSString::c_str___const_ = _const_tjs_char___tTJSString::c_str()_const__1;
    }
    v13 = _const_tjs_char___tTJSString::c_str()_const__1(a6);
    m_Pathhash_Or_Filehash_run2(v13, v16, v13, 2 * v11);
  }
  return m_Pathhash_Or_Filehash_out(v16, a4);
}
```
可以看得到，这里面的调用的函数有：
  m_Pathhash_Or_Filehash_run
  m_Pathhash_Or_Filehash_run2
  m_Pathhash_Or_Filehash_out
（均是方便读的后期命名），暂且不明确这些，先注明：run1/2和out，其实这里并不准确
需要关注的还有："uespemosmodnarodarenegylsetybdet"这个字符串，32位，多少有点用处（这不废话吗...）

我们注意到，最重要的是上面这个字符串，我们还知道，这是个哈希
这个字符串被带入了哈希函数中，不难得知这个是哈希的一部分，这个是小端序的东西，所以可以得到：

“somepseudorandomlygeneratedbytes”

这个是SipHash的特征

跟进out函数
```c
int __thiscall m_Pathhash_Or_Filehash_out(_DWORD *this, int a2)
{
  void (__stdcall *_tTJSVariant::tTJSVariant(const_tjs_uint8___tjs_uint)_)(_BYTE *, _BYTE *, int); // eax
  void (__stdcall *_tTJSVariant_&_tTJSVariant::operator__(const_tTJSVariant_&)_)(int, _BYTE *); // eax
  void (__stdcall *_tTJSVariant::__tTJSVariant()_)(_BYTE *); // eax
  _BYTE v6[12]; // [esp+8h] [ebp-24h] BYREF
  _BYTE v7[8]; // [esp+14h] [ebp-18h] BYREF
  int v8; // [esp+28h] [ebp-4h]

  m_Pathhash_Or_Filehash_Siphash(this, v7, 8u);
  _tTJSVariant::tTJSVariant(const_tjs_uint8___tjs_uint)_ = tTJSVariant::tTJSVariant_const_tjs_uint8___tjs_uint__;
  if ( !tTJSVariant::tTJSVariant_const_tjs_uint8___tjs_uint__ )
  {
    _tTJSVariant::tTJSVariant(const_tjs_uint8___tjs_uint)_ = m_throw_error(aTtjsvariantTtj_10);// "tTJSVariant::tTJSVariant(const tjs_uint8 *,tjs_uint)"
    tTJSVariant::tTJSVariant_const_tjs_uint8___tjs_uint__ = _tTJSVariant::tTJSVariant(const_tjs_uint8___tjs_uint)_;
  }
  _tTJSVariant::tTJSVariant(const_tjs_uint8___tjs_uint)_(v6, v7, 8);
  _tTJSVariant_&_tTJSVariant::operator__(const_tTJSVariant_&)_ = tTJSVariant___tTJSVariant::operator___const_tTJSVariant____;
  v8 = 0;
  if ( !tTJSVariant___tTJSVariant::operator___const_tTJSVariant____ )
  {
    _tTJSVariant_&_tTJSVariant::operator__(const_tTJSVariant_&)_ = m_throw_error(aTtjsvariantTtj_2);// "tTJSVariant & tTJSVariant::operator =(const tTJSVariant &)"
    tTJSVariant___tTJSVariant::operator___const_tTJSVariant____ = _tTJSVariant_&_tTJSVariant::operator__(const_tTJSVariant_&)_;
  }
  _tTJSVariant_&_tTJSVariant::operator__(const_tTJSVariant_&)_(a2, v6);
  _tTJSVariant::__tTJSVariant()_ = tTJSVariant::__tTJSVariant___;
  v8 = -1;
  if ( !tTJSVariant::__tTJSVariant___ )
  {
    _tTJSVariant::__tTJSVariant()_ = m_throw_error(aTtjsvariantTtj_0);// "tTJSVariant::~ tTJSVariant()"
    tTJSVariant::__tTJSVariant___ = _tTJSVariant::__tTJSVariant()_;
  }
  _tTJSVariant::__tTJSVariant()_(v6);
  return 8;
}
```

发现了真正的siphash的运行，那么也不管前面两个就不是这个的运行，回头看看这两个是什么，不过大概率猜的出来是和siphash相关的，可能是初始化之类的，可能是压缩？好吧，就是初始化和压缩，略过了。


回头看一下，最后返回的就是这个siphash了，具体的算法就不展示了

但是还记得有一个函数不是直接调用吗？

在我们回去的时候，对那个函数进行交叉引用，可以发现：在m_Pathhash_Or_Filehash_init
只有
.rdata:669019A4	dd offset m_Pathhash_Or_Filehash_init
这一个虚表调用，看看虚表是什么样


```c
.rdata:669019A0 ??_7?$DefaultCompoundHasher@UPathNameHashTrait@@@@6B@ dd offset sub_668967C0
.rdata:669019A0                                         ; DATA XREF: m_arc_setinit_DefaultCompoundHasherPathNameHashTrait+2B↑o
.rdata:669019A4                 dd offset m_Pathhash_Or_Filehash_init
.rdata:669019A8                 dd offset ??_R4?$DefaultCompoundHasher@UFileNameHashTrait@@@@6B@ ; const DefaultCompoundHasher<FileNameHashTrait>::`RTTI Complete Object Locator'
```

重点是：$DefaultCompoundHasher@UPathNameHashTrait
里面的PathNameHashTrait
声明了这就是pathnamehash的一部分

底下我们也能看见：
"$DefaultCompoundHasher@UFileNameHashTrait@@@@6B@"
里面的FileNameHashTrait，但是还是先进行动态调试，看看到底是不是这里调用到了


然后和我们之前做的一样，先进行动态调试，断点在filenamehash这里。诶，这次情况不一样了，发现断点压根断不下来，但是哈希确实被实际执行了。这只能是压根没执行这里的代码，也就是真正的哈希函数在其他位置，实际进去可以看到：
```c
int __thiscall m_arc_fileHash(_DWORD *this, int a2, int a3)
{
  int (__stdcall *_tTJSVariantType_tTJSVariant::Type()_)(int); // eax
  int v6; // esi
  void (__stdcall *_tTJSString::tTJSString(const_tTJSVariant_&)_)(_BYTE *, int); // eax
  int *v8; // eax
  void (__stdcall *_tTJSVariant::tTJSVariant(const_tTJSVariant_&)_)(_BYTE *, _BYTE *); // eax
  void (__stdcall *_tTJSVariant_&_tTJSVariant::operator__(const_tTJSVariant_&)_)(int, _BYTE *); // eax
  void (__stdcall *_tTJSVariant::__tTJSVariant()_)(_BYTE *); // eax
  void (__stdcall *_tTJSVariant::__tTJSVariant()__1)(_BYTE *); // eax
  int v13; // esi
  void (__stdcall *_void_tTJSVariantOctet::Release()_)(int); // eax
  void (__stdcall *_tTJSString::__tTJSString()_)(_BYTE *); // eax
  _BYTE v16[12]; // [esp+Ch] [ebp-28h] BYREF
  _BYTE v17[12]; // [esp+18h] [ebp-1Ch] BYREF
  _BYTE v18[4]; // [esp+24h] [ebp-10h] BYREF
  int v19; // [esp+30h] [ebp-4h]

  // 最开始是m_file_123
  _tTJSVariantType_tTJSVariant::Type()_ = tTJSVariantType_tTJSVariant::Type___;
  if ( !tTJSVariantType_tTJSVariant::Type___ )
  {
    _tTJSVariantType_tTJSVariant::Type()_ = m_throw_error(aTtjsvarianttyp);// "tTJSVariantType tTJSVariant::Type()"
    tTJSVariantType_tTJSVariant::Type___ = _tTJSVariantType_tTJSVariant::Type()_;
  }
  if ( _tTJSVariantType_tTJSVariant::Type()_(a3) != 2 )
    return -1003;
  v6 = a2;
  if ( a2 )
  {
    _tTJSString::tTJSString(const_tTJSVariant_&)_ = tTJSString::tTJSString_const_tTJSVariant____;
    if ( !tTJSString::tTJSString_const_tTJSVariant____ )
    {
      _tTJSString::tTJSString(const_tTJSVariant_&)_ = m_throw_error(aTtjsstringTtjs_5);// "tTJSString::tTJSString(const tTJSVariant &)"
      tTJSString::tTJSString_const_tTJSVariant____ = _tTJSString::tTJSString(const_tTJSVariant_&)_;
    }
    _tTJSString::tTJSString(const_tTJSVariant_&)_(v18, a3);
    v19 = 0;
    v8 = m_Filehash_run_frist(this, &a2, v18);
    LOBYTE(v19) = 1;
    m_arc_Hash_runsecond(v8, v16);
    _tTJSVariant::tTJSVariant(const_tTJSVariant_&)_ = tTJSVariant::tTJSVariant_const_tTJSVariant____;
    LOBYTE(v19) = 2;
    if ( !tTJSVariant::tTJSVariant_const_tTJSVariant____ )
    {
      _tTJSVariant::tTJSVariant(const_tTJSVariant_&)_ = m_throw_error(aTtjsvariantTtj);// "tTJSVariant::tTJSVariant(const tTJSVariant &)"
      tTJSVariant::tTJSVariant_const_tTJSVariant____ = _tTJSVariant::tTJSVariant(const_tTJSVariant_&)_;
    }
    _tTJSVariant::tTJSVariant(const_tTJSVariant_&)_(v17, v16);
    _tTJSVariant_&_tTJSVariant::operator__(const_tTJSVariant_&)_ = tTJSVariant___tTJSVariant::operator___const_tTJSVariant____;
    LOBYTE(v19) = 3;
    if ( !tTJSVariant___tTJSVariant::operator___const_tTJSVariant____ )
    {
      _tTJSVariant_&_tTJSVariant::operator__(const_tTJSVariant_&)_ = m_throw_error(aTtjsvariantTtj_2);// "tTJSVariant & tTJSVariant::operator =(const tTJSVariant &)"
      tTJSVariant___tTJSVariant::operator___const_tTJSVariant____ = _tTJSVariant_&_tTJSVariant::operator__(const_tTJSVariant_&)_;
    }
    _tTJSVariant_&_tTJSVariant::operator__(const_tTJSVariant_&)_(v6, v17);
    _tTJSVariant::__tTJSVariant()_ = tTJSVariant::__tTJSVariant___;
    LOBYTE(v19) = 2;
    if ( !tTJSVariant::__tTJSVariant___ )
    {
      _tTJSVariant::__tTJSVariant()_ = m_throw_error(aTtjsvariantTtj_0);// "tTJSVariant::~ tTJSVariant()"
      tTJSVariant::__tTJSVariant___ = _tTJSVariant::__tTJSVariant()_;
    }
    _tTJSVariant::__tTJSVariant()_(v17);
    _tTJSVariant::__tTJSVariant()__1 = tTJSVariant::__tTJSVariant___;
    LOBYTE(v19) = 1;
    if ( !tTJSVariant::__tTJSVariant___ )
    {
      _tTJSVariant::__tTJSVariant()__1 = m_throw_error(aTtjsvariantTtj_0);// "tTJSVariant::~ tTJSVariant()"
      tTJSVariant::__tTJSVariant___ = _tTJSVariant::__tTJSVariant()__1;
    }
    _tTJSVariant::__tTJSVariant()__1(v16);
    v13 = a2;
    LOBYTE(v19) = 0;
    if ( a2 )
    {
      _void_tTJSVariantOctet::Release()_ = void_tTJSVariantOctet::Release___;
      if ( !void_tTJSVariantOctet::Release___ )
      {
        _void_tTJSVariantOctet::Release()_ = m_throw_error(aVoidTtjsvarian_0);// "void tTJSVariantOctet::Release()"
        void_tTJSVariantOctet::Release___ = _void_tTJSVariantOctet::Release()_;
      }
      _void_tTJSVariantOctet::Release()_(v13);
    }
    _tTJSString::__tTJSString()_ = tTJSString::__tTJSString___;
    a2 = 0;
    v19 = -1;
    if ( !tTJSString::__tTJSString___ )
    {
      _tTJSString::__tTJSString()_ = m_throw_error(aTtjsstringTtjs_0);// "tTJSString::~ tTJSString()"
      tTJSString::__tTJSString___ = _tTJSString::__tTJSString()_;
    }
    _tTJSString::__tTJSString()_(v18);
  }
  return 0;
}
```
很轻松就发现，其实和path哈希是一个逻辑，但是实际上的filename哈希并非如此，也就是说，逻辑并没有直接跑到这里。

之前也提到的过了，函数并没被直接调用，而是被间接调用了，我们在之前的"$DefaultCompoundHasher@UFileNameHashTrait@@@@6B@"下断点
发现再次运行时，断了下来，也就是说实际被调用的是这里的函数，展开来看看

```c
int __userpurge m_hash_use_hash6900@<eax>(int a1@<ecx>, int a2@<ebx>, int a3, size_t Size, int a5)
{
  void (__stdcall *_tjs_int_tTJSString::length()_const_)(size_t, int); // eax
  int (*_const_tjs_char___tTJSString::c_str()_const_)(void); // eax
  char *v7; // eax
  int (__stdcall *_tjs_int_tTJSString::length()_const__1)(int); // eax
  int v9; // edi
  int (__stdcall *_const_tjs_char___tTJSString::c_str()_const__1)(int); // eax
  char *v11; // eax
  int v13[31]; // [esp+Ch] [ebp-80h] BYREF

  m_hash_init(v13, 0x20u, *(a1 + 4), *(a1 + 8));
  _tjs_int_tTJSString::length()_const_ = tjs_int_tTJSString::length___const_;
  if ( !tjs_int_tTJSString::length___const_ )
  {
    _tjs_int_tTJSString::length()_const_ = m_throw_error(aTjsIntTtjsstri);// "tjs_int tTJSString::length() const"
    tjs_int_tTJSString::length___const_ = _tjs_int_tTJSString::length()_const_;
  }
  _tjs_int_tTJSString::length()_const_(Size, a2);
  _const_tjs_char___tTJSString::c_str()_const_ = const_tjs_char___tTJSString::c_str___const_;
  if ( !const_tjs_char___tTJSString::c_str___const_ )
  {
    _const_tjs_char___tTJSString::c_str()_const_ = m_throw_error(aConstTjsCharTt);// "const tjs_char * tTJSString::c_str() const"
    const_tjs_char___tTJSString::c_str___const_ = _const_tjs_char___tTJSString::c_str()_const_;
  }
  v7 = _const_tjs_char___tTJSString::c_str()_const_();
  m_hash3_black2s(v13, v7, Size);
  if ( a5 )
  {
    _tjs_int_tTJSString::length()_const__1 = tjs_int_tTJSString::length___const_;
    if ( !tjs_int_tTJSString::length___const_ )
    {
      _tjs_int_tTJSString::length()_const__1 = m_throw_error(aTjsIntTtjsstri);// "tjs_int tTJSString::length() const"
      tjs_int_tTJSString::length___const_ = _tjs_int_tTJSString::length()_const__1;
    }
    v9 = _tjs_int_tTJSString::length()_const__1(a5);
    _const_tjs_char___tTJSString::c_str()_const__1 = const_tjs_char___tTJSString::c_str___const_;
    if ( !const_tjs_char___tTJSString::c_str___const_ )
    {
      _const_tjs_char___tTJSString::c_str()_const__1 = m_throw_error(aConstTjsCharTt);// "const tjs_char * tTJSString::c_str() const"
      const_tjs_char___tTJSString::c_str___const_ = _const_tjs_char___tTJSString::c_str()_const__1;
    }
    v11 = _const_tjs_char___tTJSString::c_str()_const__1(a5);
    m_hash3_black2s(v13, v11, 2 * v9);
  }
  return m_hash_use_hash6900_out(v13, a3);
}
```
（在后期被重命名）

进入init：
```c
char *__thiscall m_hash_init(char *this, unsigned int n32, void *Src, size_t Size)
{
  size_t n64; // eax
  char p_n32; // [esp+Ch] [ebp-64h] BYREF
  __int64 Size_1; // [esp+Dh] [ebp-63h]
  __int64 v9; // [esp+15h] [ebp-5Bh]
  __int64 v10; // [esp+1Dh] [ebp-53h]
  int v11; // [esp+25h] [ebp-4Bh]
  __int16 v12; // [esp+29h] [ebp-47h]
  char v13; // [esp+2Bh] [ebp-45h]
  char v14[64]; // [esp+2Ch] [ebp-44h] BYREF

  if ( n32 && n32 <= 0x20 && (Src || !Size) )
  {
    p_n32 = n32;
    v9 = 0;
    v10 = 0;
    v11 = 0;
    v12 = 0;
    v13 = 0;
    Size_1 = Size;
    *(&Size_1 + 1) = 257;
    m_hash2_black2s(this, &p_n32);
    if ( Src && Size )
    {
      memset(v14, 0, sizeof(v14));
      n64 = 64;
      if ( Size < 0x40 )
        n64 = Size;
      memmove_0(v14, Src, n64);
      m_hash3_black2s(this, v14, 0x40u);
      memset(v14, 0, sizeof(v14));
    }
  }
  else
  {
    m_hash4_black2s(this);
  }
  return this;
}
```
同样的可以看到，这是一个很标准的black2s的实现，虽然可能是会被看成其他算法，但是实际上就是不同，这里也就找齐了这两个哈希函数，接下来来写逆向算法

...吗？不行的，这是哈希函数，所以最多写出来计算器，复刻一遍哈希函数（已经写出来了，在隔壁的项目）


到此完结