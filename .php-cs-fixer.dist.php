<?php

use PhpCsFixer\Config;
use PhpCsFixer\Finder;
use PhpCsFixer\Runner\Parallel\ParallelConfigFactory;

if (!file_exists(__DIR__ . '/src') || !file_exists(__DIR__ . '/tests')) {
    exit(0);
}

return (new Config())
    // @see https://github.com/PHP-CS-Fixer/PHP-CS-Fixer/pull/7777
    ->setParallelConfig(ParallelConfigFactory::detect())
    ->setRules([
        '@PHP71Migration' => true,
        '@PHPUnit75Migration:risky' => true,
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
    ->setRiskyAllowed(true)
    ->setFinder(
        (new Finder())
            ->in(__DIR__ . '/src')
            ->in(__DIR__ . '/tests')
            ->append([__FILE__])
    )
    ->setCacheFile('.php-cs-fixer.cache');
