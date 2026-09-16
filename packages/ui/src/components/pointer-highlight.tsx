import { PointerHighlight } from "#components/ui/pointer-highlight";

export default function PointerHighlightDemo() {
  return (
    <div className="mx-auto grid max-w-4xl grid-cols-1 gap-4 py-20 sm:grid-cols-3">
      <div className="rounded-md p-6">
        <div className="h-40 w-full rounded-lg bg-linear-to-r from-blue-200 to-sky-200" />
        <div className="mx-auto mt-4 max-w-lg text-base font-bold tracking-tight md:text-base">
          <PointerHighlight
            rectangleClassName="bg-neutral-200 dark:bg-neutral-700 border-neutral-300 dark:border-neutral-600 leading-loose"
            pointerClassName="text-yellow-500 h-3 w-3"
            containerClassName="inline-block mr-1"
          >
            <span className="relative z-10">collab tool</span>
          </PointerHighlight>
          of the century with max benefits and minimal effort.
        </div>
        <p className="mt-4 text-sm text-neutral-500">
          Our state of the art collab tool of the century with max benefits.
        </p>
      </div>
      <div className="rounded-md p-6">
        <div className="h-40 w-full rounded-lg bg-linear-to-r from-blue-200 to-purple-200" />
        <div className="mx-auto mt-4 max-w-lg text-base font-bold tracking-tight md:text-base">
          Discover our
          <PointerHighlight
            rectangleClassName="bg-blue-100 dark:bg-blue-900 border-blue-300 dark:border-blue-700 leading-loose"
            pointerClassName="text-blue-500 h-3 w-3"
            containerClassName="inline-block mx-1"
          >
            <span className="relative z-10">innovative </span>
          </PointerHighlight>
          solutions for your business needs.
        </div>
        <p className="mt-4 text-sm text-neutral-500">
          Transforming ideas into reality with cutting-edge technology and
          expert guidance.
        </p>
      </div>

      <div className="rounded-md p-6">
        <div className="h-40 w-full rounded-lg bg-linear-45 from-green-200 to-yellow-200" />
        <div className="mx-auto mt-4 max-w-lg text-base font-bold tracking-tight md:text-base">
          Experience the future with our
          <PointerHighlight
            rectangleClassName="bg-green-100 dark:bg-green-900 border-green-300 dark:border-green-700 leading-loose"
            pointerClassName="text-green-500 h-3 w-3"
            containerClassName="inline-block ml-1"
          >
            <span className="relative z-10">sustainable technology</span>
          </PointerHighlight>
          .
        </div>
        <p className="mt-4 text-sm text-neutral-500">
          Eco-friendly solutions designed for a better tomorrow and reduced
          environmental impact.
        </p>
      </div>
    </div>
  );
}
