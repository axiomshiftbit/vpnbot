<?php

class Calc
{
    public function merge(array $a, array $b): array
    {
        if ($b[0] > $a[1] + 1) {
            $tmp = [$a, $b];
        } elseif ($b[1] <= $a[1]) {
            $tmp = [$a];
        } else {
            $tmp = [[$a[0], $b[1]]];
        }
        return array_filter($tmp);
    }

    public function substract(array $a, array $b): array
    {
        if ($b[0] > $a[1] || $b[1] < $a[0]) {
            return [$a];
        } elseif ($b[0] <= $a[0] && $b[1] >= $a[1]) {
            return [];
        } elseif ($b[0] > $a[0] && $b[1] < $a[1]) {
            return [[$a[0], $b[0] - 1], [$b[1] + 1, $a[1]]];
        } elseif ($b[0] <= $a[0]) {
            return [[$b[1] + 1, $a[1]]];
        } else {
            return [[$a[0], $b[0] - 1]];
        }
    }

    public function alignment(array $arr): array
    {
        usort($arr, fn ($a, $b) => $a[0] <=> $b[0]);
        // Затравка [[]] уходила первым аргументом в merge(), где читаются $a[0]
        // и $a[1]: «Undefined array key 1» на КАЖДОМ вызове, а для диапазона,
        // начинающегося с 0/1, ветка else давала ещё и битый [null, $b[1]]
        // (null+1 = 1, поэтому $b[0] > $a[1]+1 не срабатывало).
        // Первый элемент просто берём как есть — сливать его не с чем.
        $tmp = [];
        foreach ($arr as $v) {
            if (empty($tmp)) {
                $tmp = [$v];
                continue;
            }
            $t   = array_pop($tmp);
            $tmp = array_merge($tmp, $this->merge($t, $v));
        }
        return $tmp;
    }

    public function prepare(array $include, array $exclude): array
    {
        $include = $this->alignment($include);
        if (!empty($exclude)) {
            $exclude = $this->alignment($exclude);
            $result  = $include;
            // Каждый exclude вычитаем из ТЕКУЩЕГО результата, а не из исходного
            // include, иначе при >1 исключении диапазоны накапливаются с дублями.
            foreach ($exclude as $v) {
                $tmp = [];
                foreach ($result as $j) {
                    $tmp = array_merge($tmp, $this->substract($j, $v));
                }
                $result = $tmp;
            }
            return $result;
        }
        return $include;
    }

    /**
     * Диапазон адресов → список CIDR-блоков.
     *
     * Блок обязан быть ВЫРОВНЕН по своей границе: 1.0.0.1/30 канонически
     * означает 1.0.0.0–1.0.0.3, то есть прежний вывод для 1.0.0.1–1.0.0.4
     * захватывал 1.0.0.0 и терял 1.0.0.4. Теперь на каждом шаге берётся
     * наибольший блок, который одновременно начинается на текущем адресе и
     * не вылезает за конец диапазона.
     */
    public function toCIDR(int $a, int $b)
    {
        $tmp = [];
        while ($a <= $b) {
            $count = $b - $a + 1;
            $bits  = 0;
            while ($bits < 32 && (1 << ($bits + 1)) <= $count) {
                $bits++;
            }
            while ($bits > 0 && ($a % (1 << $bits)) !== 0) {
                $bits--;
            }
            $tmp[] = long2ip($a) . '/' . (32 - $bits);
            $a += 1 << $bits;
        }
        return $tmp;
    }
}
