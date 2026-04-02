<?php

declare(strict_types=1);

use PhpCsFixer\Config;
use PhpCsFixer\Finder;
use PhpCsFixer\Runner\Parallel\ParallelConfigFactory;

return (new Config())
    ->setParallelConfig(ParallelConfigFactory::detect())
    ->setRiskyAllowed(true)
    ->setRules([
        '@PHP8x2Migration' => true,
        '@PHPUnit10x0Migration:risky' => true,
        '@Symfony' => true,
        '@Symfony:risky' => true,
        'protected_to_private' => false,
        'phpdoc_annotation_without_dot' => false,
        'increment_style' => [
            'style' => 'post',
        ],
        'phpdoc_types_order' => [
            'null_adjustment' => 'always_first',
        ],
        'concat_space' => [
            'spacing' => 'one',
        ],
    ])
    ->setFinder(
        (new Finder())
            ->in(__DIR__ . '/src')
            ->in(__DIR__ . '/tests')
            ->append([__FILE__])
    )
    ->setCacheFile('.php-cs-fixer.cache');
