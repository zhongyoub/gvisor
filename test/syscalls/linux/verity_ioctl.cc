// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <sys/mount.h>

#include <iomanip>
#include <sstream>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/fs_util.h"
#include "test/util/mount_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

#ifndef FS_IOC_ENABLE_VERITY
#define FS_IOC_ENABLE_VERITY 1082156677
#endif

#ifndef FS_IOC_MEASURE_VERITY
#define FS_IOC_MEASURE_VERITY 3221513862
#endif

#ifndef FS_VERITY_FL
#define FS_VERITY_FL 1048576
#endif

#ifndef FS_IOC_GETFLAGS
#define FS_IOC_GETFLAGS 2148034049
#endif

struct fsverity_digest {
  __u16 digest_algorithm;
  __u16 digest_size; /* input/output */
  __u8 digest[];
};

const int fsverity_max_digest_size = 64;
const int fsverity_default_digest_size = 32;
constexpr char kContents[] = "foobarbaz";

class IoctlTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Verity is implemented in VFS2.
    SKIP_IF(IsRunningWithVFS1());

    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
    // Mount a tmpfs file system, to be wrapped by a verity fs.
    tmpfs_dir_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    ASSERT_THAT(mount("", tmpfs_dir_.path().c_str(), "tmpfs", 0, ""),
                SyscallSucceeds());

    // Create a new file in the tmpfs mount.
    file_ = ASSERT_NO_ERRNO_AND_VALUE(
        TempPath::CreateFileWith(tmpfs_dir_.path(), kContents, 0777));
    filename_ = Basename(file_.path());
  }

  TempPath tmpfs_dir_;
  TempPath file_;
  std::string filename_;
};

TEST_F(IoctlTest, Enable) {
  // Mount a verity fs on the existing tmpfs mount.
  std::string mount_opts = "lower_path=" + tmpfs_dir_.path();
  auto const verity_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(
      mount("", verity_dir.path().c_str(), "verity", 0, mount_opts.c_str()),
      SyscallSucceeds());

  printf("verity path: %s, filename: %s\n", verity_dir.path().c_str(),
         filename_.c_str());
  fflush(nullptr);
  // Confirm that the verity flag is absent.
  int flag = 0;
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(verity_dir.path(), filename_), O_RDONLY, 0777));
  ASSERT_THAT(ioctl(fd.get(), FS_IOC_GETFLAGS, &flag), SyscallSucceeds());
  EXPECT_EQ(flag & FS_VERITY_FL, 0);

  // Enable the file and confirm that the verity flag is present.
  ASSERT_THAT(ioctl(fd.get(), FS_IOC_ENABLE_VERITY), SyscallSucceeds());
  ASSERT_THAT(ioctl(fd.get(), FS_IOC_GETFLAGS, &flag), SyscallSucceeds());
  EXPECT_EQ(flag & FS_VERITY_FL, FS_VERITY_FL);
}

TEST_F(IoctlTest, Measure) {
  // Mount a verity fs on the existing tmpfs mount.
  std::string mount_opts = "lower_path=" + tmpfs_dir_.path();
  auto const verity_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(
      mount("", verity_dir.path().c_str(), "verity", 0, mount_opts.c_str()),
      SyscallSucceeds());

  // Confirm that the file cannot be measured.
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(verity_dir.path(), filename_), O_RDONLY, 0777));
  int digest_size = sizeof(struct fsverity_digest) + fsverity_max_digest_size;
  struct fsverity_digest *digest =
      reinterpret_cast<struct fsverity_digest *>(malloc(digest_size));
  memset(digest, 0, digest_size);
  digest->digest_size = fsverity_max_digest_size;
  ASSERT_THAT(ioctl(fd.get(), FS_IOC_MEASURE_VERITY, digest),
              SyscallFailsWithErrno(ENODATA));

  // Enable the file and confirm that the file can be measured.
  ASSERT_THAT(ioctl(fd.get(), FS_IOC_ENABLE_VERITY), SyscallSucceeds());
  ASSERT_THAT(ioctl(fd.get(), FS_IOC_MEASURE_VERITY, digest),
              SyscallSucceeds());
  EXPECT_EQ(digest->digest_size, fsverity_default_digest_size);
  free(digest);
}

TEST_F(IoctlTest, Mount) {
  // Mount a verity fs on the existing tmpfs mount.
  std::string mount_opts = "lower_path=" + tmpfs_dir_.path();
  auto verity_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(
      mount("", verity_dir.path().c_str(), "verity", 0, mount_opts.c_str()),
      SyscallSucceeds());

  // Enable both the file and the directory.
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(verity_dir.path(), filename_), O_RDONLY, 0777));
  ASSERT_THAT(ioctl(fd.get(), FS_IOC_ENABLE_VERITY), SyscallSucceeds());
  auto const dir_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(verity_dir.path(), O_RDONLY, 0777));
  ASSERT_THAT(ioctl(dir_fd.get(), FS_IOC_ENABLE_VERITY), SyscallSucceeds());

  // Measure the root hash.
  int digest_size = sizeof(struct fsverity_digest) + fsverity_max_digest_size;
  struct fsverity_digest *digest =
      reinterpret_cast<struct fsverity_digest *>(malloc(digest_size));
  memset(digest, 0, digest_size);
  digest->digest_size = fsverity_max_digest_size;
  ASSERT_THAT(ioctl(dir_fd.get(), FS_IOC_MEASURE_VERITY, digest),
              SyscallSucceeds());

  // Mount a verity fs with specified root hash.
  std::stringstream strDigest;
  strDigest << std::hex;
  for (int i = 0; i < digest->digest_size; ++i) {
    strDigest << std::setw(2) << std::setfill('0')
              << static_cast<int>(digest->digest[i]);
  }
  free(digest);
  mount_opts += ",root_hash=" + strDigest.str();
  auto verity_with_hash_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount("", verity_with_hash_dir.path().c_str(), "verity", 0,
                    mount_opts.c_str()),
              SyscallSucceeds());

  // Make sure the file can be open and read in the mounted verity fs.
  auto const verity_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(verity_with_hash_dir.path(), filename_), O_RDONLY, 0777));
  char buf[16];
  EXPECT_THAT(ReadFd(fd.get(), buf, sizeof(kContents)), SyscallSucceeds());
  EXPECT_THAT(buf, ::testing::StrEq(kContents));

  // Verity directories should not be deleted.
  verity_dir.release();
  verity_with_hash_dir.release();
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
