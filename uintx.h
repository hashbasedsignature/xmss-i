#ifndef UINTX_H
#define UINTX_H

#include <stdint.h>
#include <stdbool.h>

typedef uint64_t uint128_t[2];

bool less_u128(const uint128_t *x, const uint128_t *y)
{
  return (*x)[1] < (*y)[1] || ((*x)[1] == (*y)[1] && (*x)[0] < (*y)[0]);
}

bool eq_u128(const uint128_t *x, const uint128_t *y)
{
  return ((*x)[1] == (*y)[1] && (*x)[0] == (*y)[0]);
}

void add_u128(uint128_t *z, const uint128_t *x, const uint128_t *y)
{
  uint64_t c = ((*x)[0] > UINT64_MAX - (*y)[0] ? 1 : 0);
  (*z)[0] = (*x)[0] + (*y)[0];
  (*z)[1] = (*x)[1] + (*y)[1] + c;
}

void sub_u128(uint128_t *z, const uint128_t *x, const uint128_t *y)
{
  uint64_t c = ((*x)[0] < (*y)[0]);
  (*z)[0] = (*x)[0] - (*y)[0];
  (*z)[1] = (*x)[1] - (*y)[1] - c;
}

void set0_u128(uint128_t *z)
{
  uint64_t *t = (uint64_t *)z;
  t[0] = t[1] = 0;
}

void set1_u128(uint128_t *z)
{
  uint64_t *t = (uint64_t *)z;
  t[0] = 1;
  t[1] = 0;
}
static const uint128_t UINT128_MAX = {~0ULL, ~0ULL};

typedef uint64_t uint256_t[4];

bool less_u256(const uint256_t *x, const uint256_t *y)
{
  for (int32_t i = 3; i >= 0; i--)
  {
    if ((*x)[i] != (*y)[i])
      return (*x)[i] < (*y)[i];
  }
  return false;
}

void set0_u256(uint256_t *z)
{
  (*z)[0] = (*z)[1] = (*z)[2] = (*z)[3] = 0;
}
void set1_u256(uint256_t *z)
{
  (*z)[0] = 1;
  (*z)[1] = (*z)[2] = (*z)[3] = 0;
}

void add_u256(uint256_t *z, const uint256_t *x, const uint256_t *y)
{

  const uint128_t *x0 = (const uint128_t *)&(*x)[0];
  const uint128_t *x1 = (const uint128_t *)&(*x)[2];
  const uint128_t *y0 = (const uint128_t *)&(*y)[0];
  const uint128_t *y1 = (const uint128_t *)&(*y)[2];
  uint128_t *z0 = (uint128_t *)&(*z)[0];
  uint128_t *z1 = (uint128_t *)&(*z)[2];

  uint128_t tmp;
  sub_u128(&tmp, &UINT128_MAX, y0);
  uint128_t c = {less_u128((const uint128_t *)&tmp, x0) ? 1 : 0, 0};
  add_u128(z0, x0, y0);
  add_u128(z1, x1, y1);
  add_u128(z1, (const uint128_t *)z1, (const uint128_t *)&c);
}

void sub_u256(uint256_t *z, const uint256_t *x, const uint256_t *y)
{
  const uint128_t *x0 = (const uint128_t *)&(*x)[0];
  const uint128_t *x1 = (const uint128_t *)&(*x)[2];
  const uint128_t *y0 = (const uint128_t *)&(*y)[0];
  const uint128_t *y1 = (const uint128_t *)&(*y)[2];
  uint128_t *z0 = (uint128_t *)&(*z)[0];
  uint128_t *z1 = (uint128_t *)&(*z)[2];

  uint128_t c = {less_u128(x0, y0) ? 1 : 0, 0};
  sub_u128(z0, x0, y0);
  sub_u128(z1, x1, y1);
  sub_u128(z1, (const uint128_t *)z1, (const uint128_t *)&c);
}

//512
static const uint256_t UINT256_MAX = {~0ULL, ~0ULL,~0ULL, ~0ULL};

typedef uint64_t uint512_t[8];

bool less_u512(const uint512_t *x, const uint512_t *y)
{
  for (int32_t i = 7; i >= 0; i--)
  {
    if ((*x)[i] != (*y)[i])
      return (*x)[i] < (*y)[i];
  }
  return false;
}

void set0_u512(uint512_t *z)
{
  (*z)[0] = (*z)[1] = (*z)[2] = (*z)[3] = 0;
  (*z)[4] = (*z)[5] = (*z)[6] = (*z)[7] = 0;
}
void set1_u512(uint512_t *z)
{
  (*z)[0] = 1;
  (*z)[1] = (*z)[2] = (*z)[3] = 0;
  (*z)[4] = (*z)[5] = (*z)[6] = (*z)[7] = 0;
}

void add_u512(uint512_t *z, const uint512_t *x, const uint512_t *y)
{

  const uint256_t *x0 = (const uint256_t *)&(*x)[0];
  const uint256_t *x1 = (const uint256_t *)&(*x)[4];
  const uint256_t *y0 = (const uint256_t *)&(*y)[0];
  const uint256_t *y1 = (const uint256_t *)&(*y)[4];
  uint256_t *z0 = (uint256_t *)&(*z)[0];
  uint256_t *z1 = (uint256_t *)&(*z)[4];

  uint256_t tmp;
  sub_u256(&tmp, &UINT256_MAX, y0);
  uint256_t c = {less_u256((const uint256_t *)&tmp, x0) ? 1 : 0, 0};
  add_u256(z0, x0, y0);
  add_u256(z1, x1, y1);
  add_u256(z1, (const uint256_t *)z1, (const uint256_t *)&c);
}

void sub_u512(uint512_t *z, const uint512_t *x, const uint512_t *y)
{
  const uint256_t *x0 = (const uint256_t *)&(*x)[0];
  const uint256_t *x1 = (const uint256_t *)&(*x)[4];
  const uint256_t *y0 = (const uint256_t *)&(*y)[0];
  const uint256_t *y1 = (const uint256_t *)&(*y)[4];
  uint256_t *z0 = (uint256_t *)&(*z)[0];
  uint256_t *z1 = (uint256_t *)&(*z)[4];

  uint256_t c = {less_u256(x0, y0) ? 1 : 0, 0};
  sub_u256(z0, x0, y0);
  sub_u256(z1, x1, y1);
  sub_u256(z1, (const uint256_t *)z1, (const uint256_t *)&c);
}

#endif