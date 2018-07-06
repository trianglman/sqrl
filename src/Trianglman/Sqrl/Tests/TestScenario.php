<?php
namespace Trianglman\Sqrl\Tests;

use PHPUnit\Framework\TestCase;

abstract class TestScenario
{
    /**
     * @var TestCase
     */
    protected $test;

    public function __construct(TestCase $test)
    {
        $this->test = $test;
    }

    /**
     * Sets up the data that would be set on the server end before the scenario happens
     *
     * @param callable $run
     *
     * @return TestScenario
     */
    public function given(callable $run): TestScenario
    {
        $run();
        return $this;
    }

    /**
     * Describes the scenario happening
     *
     * @param callable $run
     *
     * @return TestScenario
     */
    public function when(callable $run): TestScenario
    {
        $run();
        return $this;
    }

    /**
     * @param callable $run
     */
    public function then(callable $run): void
    {
        $run();
    }
}